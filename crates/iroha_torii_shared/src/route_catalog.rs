//! Canonical metadata for Torii HTTP routes.
//!
//! The catalog is deliberately independent of an HTTP framework. Torii uses it
//! to decide which routes are mounted for a build, while documentation and
//! client tooling consume explicit projections of the same descriptors.
use std::collections::{BTreeMap, BTreeSet};
#[path = "route_catalog/path_shape.rs"]
mod path_shape;
use path_shape::normalized_route_shape;
/// First-release schema version for route authentication and admission metadata.
///
/// Every catalog projection carries this value through [`RouteDescriptor`]. A
/// consumer must reject descriptors with a different version instead of
/// guessing the meaning of [`AuthenticationPolicy`] or [`AdmissionPolicy`].
pub const ROUTE_AUTH_METADATA_SCHEMA_VERSION_V1: u16 = 1;
/// HTTP methods supported by the Torii route catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HttpMethod {
    /// Match every HTTP method for a protocol-native gateway route.
    Any,
    /// Retrieve a resource or collection.
    Get,
    /// Submit a command or create a subordinate resource.
    Post,
    /// Replace a resource completely.
    Put,
    /// Update part of a resource.
    Patch,
    /// Delete a resource.
    Delete,
}
impl HttpMethod {
    /// Return the canonical uppercase spelling of the method.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Any => "ANY",
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }
}
/// Security and audience boundary for a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApiSurface {
    /// Application-facing API available through the public Torii listener.
    Public,
    /// Privileged administration API available through the operator listener.
    Operator,
    /// Operational diagnostics available only through the diagnostic listener.
    Diagnostic,
    /// Protocol-native endpoint whose listener is declared independently.
    Protocol,
}
/// Listener on which a route is eligible to be mounted.
///
/// Torii currently exposes one HTTP listener. Audience and authentication are therefore modeled
/// separately by [`ApiSurface`] and [`AuthenticationPolicy`] instead of pretending that operator or
/// diagnostic routes have a network boundary which does not exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Listener {
    /// The single configured Torii HTTP listener.
    Torii,
}
/// Application transport used by a route after the HTTP request is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteTransport {
    /// Bounded HTTP request and response.
    Http,
    /// Server-sent event stream.
    ServerSentEvents,
    /// WebSocket session established through an HTTP upgrade.
    WebSocket,
}
/// Authentication contract enforced by the route boundary.
///
/// Most policies are middleware-backed. Protocol exchanges and explicitly reviewed handlers may
/// enforce their credential at the handler boundary, before invoking a protected capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthenticationPolicy {
    /// The listener's configured API-token policy applies.
    ToriiDefault,
    /// Require an actual owner listener token and an immutable private-root identity inside the handler.
    PrivateRootOwnerToken,
    /// Apply listener token policy and require one dedicated signer-backed onboarding token.
    OnboardingToken,
    /// Require canonical `X-Iroha-*` authentication bound to an on-ledger account.
    CanonicalAccountSignature,
    /// Permit an anonymous public-dataspace read, or verify canonical
    /// `X-Iroha-*` authentication to expand the read to caller-visible
    /// restricted dataspaces.
    OptionalCanonicalAccountSignature,
    /// The handler verifies a canonical signed transaction, query, or typed intent after bounded
    /// framing/shape parsing and before fee, state, or expensive principal-owned work.
    CanonicalSignedBody,
    /// Access is selected by the authenticated content manifest.
    ///
    /// `Public` manifests admit anonymous reads. `RoleGate` and `Sponsor`
    /// manifests require canonical account request authentication followed by
    /// current-state role or sponsor authorization inside the handler.
    ManifestConditionalContent,
    /// The route requires an operator-style request signature bound to a
    /// handler-validated dynamic key identity.
    IdentityBoundSignature,
    /// Require an allow-listed exact-network operator signature; optional WebAuthn/mTLS can add a second factor, while sessions and bearer tokens never satisfy it.
    OperatorSignature,
    /// The operator credential exchange authenticates inside the handler.
    ///
    /// `WebAuthn` registration and login cannot require an already-established operator signature:
    /// registration accepts the dedicated operator bootstrap token only until the first credential,
    /// while login verifies a `WebAuthn` challenge. Afterward only an authenticated session may
    /// enroll rollover credentials. The handlers still enforce mTLS, rate limits, lockout, and
    /// challenge verification as appropriate; listener API tokens never enter this boundary.
    OperatorCredentialExchange,
    /// The protocol performs authentication inside its own handshake.
    ProtocolHandshake,
    /// A bounded protocol gateway dispatches only into cataloged routes and
    /// preserves each selected route's authoritative authentication boundary.
    NestedRouteAuthentication,
    /// The route is intentionally usable without route-specific credentials.
    /// Listener-wide controls can still restrict this route.
    Unauthenticated,
}
impl AuthenticationPolicy {
    /// Return the canonical first-release metadata label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ToriiDefault => "torii_default",
            Self::PrivateRootOwnerToken => "private_root_owner_token",
            Self::OnboardingToken => "onboarding_token",
            Self::CanonicalAccountSignature => "canonical_account_signature",
            Self::OptionalCanonicalAccountSignature => "optional_canonical_account_signature",
            Self::CanonicalSignedBody => "canonical_signed_body",
            Self::ManifestConditionalContent => "manifest_conditional_content",
            Self::IdentityBoundSignature => "identity_bound_signature",
            Self::OperatorSignature => "operator_signature",
            Self::OperatorCredentialExchange => "operator_credential_exchange",
            Self::ProtocolHandshake => "protocol_handshake",
            Self::NestedRouteAuthentication => "nested_route_authentication",
            Self::Unauthenticated => "unauthenticated",
        }
    }
    /// Return whether every response from this authentication boundary must be private and
    /// non-cacheable.
    #[must_use]
    pub const fn requires_private_no_store(self) -> bool {
        matches!(
            self,
            Self::PrivateRootOwnerToken
                | Self::OnboardingToken
                | Self::CanonicalAccountSignature
                | Self::OptionalCanonicalAccountSignature
                | Self::OperatorSignature
                | Self::OperatorCredentialExchange
        )
    }
}
/// Deterministic effect class for one Torii route. The classification describes the strongest
/// server-side effect reachable through the route. A handler which can both read and mutate is
/// therefore a [`Mutation`](Self::Mutation), while a transport which remains open is a
/// [`LongLivedStream`](Self::LongLivedStream).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteEffect {
    /// Bounded reads which neither mutate durable state nor enqueue retained work.
    ReadOnly,
    /// Bounded but attacker-amplifiable computation, including proof jobs.
    ExpensiveCompute,
    /// Ledger, durable-service, or retained-job mutation.
    Mutation,
    /// SSE or WebSocket response which deliberately remains open.
    LongLivedStream,
}
/// Principal eligibility required before a route may perform its effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdmissionPolicy {
    /// No application principal is required.
    Public,
    /// A canonical on-ledger account principal is required.
    AuthenticatedAccount,
    /// Anonymous callers may read public dataspaces; a verified ledger account
    /// may additionally read its current restricted-dataspace scope.
    DataspaceVisible,
    /// A non-ledger principal authenticated by a protocol handshake or private-root owner token is required.
    AuthenticatedProtocolPrincipal,
    /// A current validator or roster member is required.
    ValidatorRosterMember,
    /// A governed auditor active for the exact policy and key epoch is required.
    ///
    /// Identity-bound middleware authenticates the submitted key. The route
    /// handler must additionally authorize that key against current governed
    /// auditor state before it reads a capsule or accepts an approval.
    GovernedAuditor,
    /// A node operator principal is required.
    Operator,
    /// The exact nested target route admits its own account, validator, operator, signed-body, or
    /// public-read principal before any target effect is performed.
    TargetRoute,
}
impl AdmissionPolicy {
    /// Return the canonical first-release metadata label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::AuthenticatedAccount => "authenticated_account",
            Self::DataspaceVisible => "dataspace_visible",
            Self::AuthenticatedProtocolPrincipal => "authenticated_protocol_principal",
            Self::ValidatorRosterMember => "validator_roster_member",
            Self::GovernedAuditor => "governed_auditor",
            Self::Operator => "operator",
            Self::TargetRoute => "target_route",
        }
    }
}
/// Router path normalization accepted by a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathNormalization {
    /// Match the declared path exactly; do not add trailing-slash redirects or
    /// duplicate-slash/case aliases.
    Strict,
}
/// How the router matches the path declared by a descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteMatch {
    /// Match only the exact path shape.
    Exact,
    /// Match a final `{*parameter}` wildcard segment.
    Wildcard,
}
/// Whether a path follows the canonical `/v1` grammar or is a reviewed exception.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathPolicy {
    /// Apply the canonical `/v1` path grammar.
    CanonicalV1,
    /// Permit a protocol-native path outside the canonical grammar.
    ProtocolException {
        /// Non-empty review rationale for the exception.
        reason: &'static str,
    },
}
/// Feature/capability expression controlling whether a route is available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FeatureGate {
    /// The route is available in every build.
    Always,
    /// The route requires one named build feature or runtime capability.
    Feature(&'static str),
    /// The route requires all listed build features or runtime capabilities.
    All(&'static [&'static str]),
    /// The route requires at least one listed build feature or runtime capability.
    Any(&'static [&'static str]),
}
impl FeatureGate {
    /// Determine whether this expression is satisfied by `features`.
    #[must_use]
    pub fn is_enabled(self, features: EnabledFeatures<'_>) -> bool {
        match self {
            Self::Always => true,
            Self::Feature(name) => features.contains(name),
            Self::All(names) => names.iter().all(|name| features.contains(name)),
            Self::Any(names) => names.iter().any(|name| features.contains(name)),
        }
    }
}
/// Features enabled for one catalog projection.
#[derive(Debug, Clone, Copy, Default)]
pub struct EnabledFeatures<'a> {
    names: &'a [&'a str],
}
impl<'a> EnabledFeatures<'a> {
    /// Construct a feature set from canonical Cargo feature names.
    #[must_use]
    pub const fn new(names: &'a [&'a str]) -> Self {
        Self { names }
    }
    /// Construct an empty feature set.
    #[must_use]
    pub const fn none() -> Self {
        Self { names: &[] }
    }
    /// Return whether `name` is enabled.
    #[must_use]
    pub fn contains(self, name: &str) -> bool {
        self.names.contains(&name)
    }
}
/// Explicit documentation and tooling exposure decisions for a route.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct RouteProjections(u8);
impl RouteProjections {
    const OPENAPI_BIT: u8 = 1 << 0;
    const SDK_BIT: u8 = 1 << 1;
    const MCP_BIT: u8 = 1 << 2;
    /// Do not expose the route through a generated projection.
    pub const NONE: Self = Self(0);
    /// Expose the route in `OpenAPI` only.
    pub const OPENAPI: Self = Self(Self::OPENAPI_BIT);
    /// Expose the route to generated SDKs only.
    pub const SDK: Self = Self(Self::SDK_BIT);
    /// Expose the route as an explicitly allowlisted MCP operation only.
    pub const MCP: Self = Self(Self::MCP_BIT);
    /// Expose the route in `OpenAPI` and generated SDKs.
    pub const OPENAPI_AND_SDK: Self = Self(Self::OPENAPI_BIT | Self::SDK_BIT);
    /// Expose the route in every generated projection.
    pub const ALL: Self = Self(Self::OPENAPI_BIT | Self::SDK_BIT | Self::MCP_BIT);
    /// Return whether the route belongs in the `OpenAPI` projection.
    #[must_use]
    pub const fn openapi(self) -> bool {
        self.0 & Self::OPENAPI_BIT != 0
    }
    /// Return whether the route belongs in the canonical SDK projection.
    #[must_use]
    pub const fn sdk(self) -> bool {
        self.0 & Self::SDK_BIT != 0
    }
    /// Return whether the route is explicitly allowlisted for MCP.
    #[must_use]
    pub const fn mcp(self) -> bool {
        self.0 & Self::MCP_BIT != 0
    }
    /// Combine two projection sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}
/// A consumer-specific view of the canonical route catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CatalogProjection {
    /// Routes mounted by a build with the supplied features.
    Mounted,
    /// Enabled routes explicitly included in `OpenAPI`.
    OpenApi,
    /// Canonical SDK superset, independent of one node's enabled features.
    Sdk,
    /// Enabled routes explicitly allowlisted for MCP.
    Mcp,
}
/// A framework-level route which is intentionally not an application
/// operation in `OpenAPI`, SDK, or MCP projections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ImplicitRouteKind {
    /// CORS middleware may terminate a preflight OPTIONS request before the application handler.
    CorsOptions,
}
/// Manifest entry for framework-generated HTTP behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ImplicitRouteDescriptor {
    parent_route_id: &'static str,
    path: &'static str,
    kind: ImplicitRouteKind,
}
impl ImplicitRouteDescriptor {
    /// Return the explicit route which authorizes this framework behavior.
    #[must_use]
    pub const fn parent_route_id(self) -> &'static str {
        self.parent_route_id
    }
    /// Return the exact path affected by the framework behavior.
    #[must_use]
    pub const fn path(self) -> &'static str {
        self.path
    }
    /// Return the framework behavior kind.
    #[must_use]
    pub const fn kind(self) -> ImplicitRouteKind {
        self.kind
    }
}
/// Static metadata describing one canonical Torii route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RouteDescriptor {
    auth_metadata_schema_version: u16,
    stable_route_id: &'static str,
    method: HttpMethod,
    path: &'static str,
    surface: ApiSurface,
    listener: Listener,
    effect: RouteEffect,
    transport: RouteTransport,
    admission: AdmissionPolicy,
    authentication: AuthenticationPolicy,
    feature_gate: FeatureGate,
    projections: RouteProjections,
    route_match: RouteMatch,
    path_policy: PathPolicy,
    path_normalization: PathNormalization,
    private_no_store: bool,
    cors_options: bool,
}
impl RouteDescriptor {
    /// Construct a bounded HTTP route with explicit effect and admission metadata. No effect or
    /// admission default exists; streaming routes must also replace the default HTTP transport.
    #[must_use]
    pub const fn new(
        stable_route_id: &'static str,
        method: HttpMethod,
        path: &'static str,
        surface: ApiSurface,
        listener: Listener,
        effect: RouteEffect,
        admission: AdmissionPolicy,
    ) -> Self {
        Self {
            auth_metadata_schema_version: ROUTE_AUTH_METADATA_SCHEMA_VERSION_V1,
            stable_route_id,
            method,
            path,
            surface,
            listener,
            effect,
            transport: RouteTransport::Http,
            admission,
            authentication: AuthenticationPolicy::ToriiDefault,
            feature_gate: FeatureGate::Always,
            projections: RouteProjections::NONE,
            route_match: RouteMatch::Exact,
            path_policy: PathPolicy::CanonicalV1,
            path_normalization: PathNormalization::Strict,
            private_no_store: false,
            cors_options: false,
        }
    }
    /// Set the build-feature expression for the route.
    #[must_use]
    pub const fn with_feature_gate(mut self, feature_gate: FeatureGate) -> Self {
        self.feature_gate = feature_gate;
        self
    }
    /// Set the route-specific authentication policy.
    #[must_use]
    pub const fn with_authentication(mut self, authentication: AuthenticationPolicy) -> Self {
        self.authentication = authentication;
        self
    }
    /// Replace the explicitly declared effect with a more precise classification.
    #[must_use]
    pub const fn with_effect(mut self, effect: RouteEffect) -> Self {
        self.effect = effect;
        self
    }
    /// Set the application transport used after request admission.
    #[must_use]
    pub const fn with_transport(mut self, transport: RouteTransport) -> Self {
        self.transport = transport;
        self
    }
    /// Replace the explicitly declared admission policy with a more precise classification.
    #[must_use]
    pub const fn with_admission(mut self, admission: AdmissionPolicy) -> Self {
        self.admission = admission;
        self
    }
    /// Set generated documentation and tooling projections.
    #[must_use]
    pub const fn with_projections(mut self, projections: RouteProjections) -> Self {
        self.projections = projections;
        self
    }
    /// Set the router match behavior.
    #[must_use]
    pub const fn with_route_match(mut self, route_match: RouteMatch) -> Self {
        self.route_match = route_match;
        self
    }
    /// Set the path grammar policy.
    #[must_use]
    pub const fn with_path_policy(mut self, path_policy: PathPolicy) -> Self {
        self.path_policy = path_policy;
        self
    }
    /// Require every response from this route to be private and non-cacheable.
    #[must_use]
    pub const fn with_private_no_store(mut self) -> Self {
        self.private_no_store = true;
        self
    }
    /// Declare whether CORS middleware may answer OPTIONS for this path.
    #[must_use]
    pub const fn with_cors_options(mut self, cors_options: bool) -> Self {
        self.cors_options = cors_options;
        self
    }
    /// Return the stable, low-cardinality telemetry and generation identifier.
    #[must_use]
    pub const fn stable_route_id(self) -> &'static str {
        self.stable_route_id
    }
    /// Return the HTTP method.
    #[must_use]
    pub const fn method(self) -> HttpMethod {
        self.method
    }
    /// Return the canonical router path.
    #[must_use]
    pub const fn path(self) -> &'static str {
        self.path
    }
    /// Return the security and audience surface.
    #[must_use]
    pub const fn surface(self) -> ApiSurface {
        self.surface
    }
    /// Return the listener on which the route is mounted.
    #[must_use]
    pub const fn listener(self) -> Listener {
        self.listener
    }
    /// Return the strongest server-side effect reachable through the route.
    #[must_use]
    pub const fn effect(self) -> RouteEffect {
        self.effect
    }
    /// Return the application transport used after request admission.
    #[must_use]
    pub const fn transport(self) -> RouteTransport {
        self.transport
    }
    /// Return the principal eligibility required before executing the route.
    #[must_use]
    pub const fn admission(self) -> AdmissionPolicy {
        self.admission
    }
    /// Return the route-specific authentication policy.
    #[must_use]
    pub const fn authentication(self) -> AuthenticationPolicy {
        self.authentication
    }
    /// Return the build-feature expression.
    #[must_use]
    pub const fn feature_gate(self) -> FeatureGate {
        self.feature_gate
    }
    /// Return the explicit generated projections.
    #[must_use]
    pub const fn projections(self) -> RouteProjections {
        self.projections
    }
    /// Return the router match behavior.
    #[must_use]
    pub const fn route_match(self) -> RouteMatch {
        self.route_match
    }
    /// Return the path grammar policy.
    #[must_use]
    pub const fn path_policy(self) -> PathPolicy {
        self.path_policy
    }
    /// Return the path normalization policy.
    #[must_use]
    pub const fn path_normalization(self) -> PathNormalization {
        self.path_normalization
    }
    /// Return whether authentication or route-specific policy requires private non-caching.
    #[must_use]
    pub const fn requires_private_no_store(self) -> bool {
        self.private_no_store || self.authentication.requires_private_no_store()
    }
    /// Return whether CORS middleware may answer OPTIONS.
    #[must_use]
    pub const fn cors_options(self) -> bool {
        self.cors_options
    }
    /// Return the version governing this descriptor's authentication and admission metadata.
    #[must_use]
    pub const fn auth_metadata_schema_version(self) -> u16 {
        self.auth_metadata_schema_version
    }
    fn is_in_projection(
        self,
        projection: CatalogProjection,
        features: EnabledFeatures<'_>,
    ) -> bool {
        match projection {
            CatalogProjection::Mounted => self.feature_gate.is_enabled(features),
            CatalogProjection::OpenApi => {
                self.projections.openapi() && self.feature_gate.is_enabled(features)
            }
            CatalogProjection::Sdk => self.projections.sdk(),
            CatalogProjection::Mcp => {
                self.projections.mcp() && self.feature_gate.is_enabled(features)
            }
        }
    }
}
/// Read-only view over a canonical set of route descriptors.
#[derive(Debug, Clone, Copy)]
pub struct RouteCatalog<'a> {
    routes: &'a [RouteDescriptor],
}
impl<'a> RouteCatalog<'a> {
    /// Construct a catalog over `routes`.
    #[must_use]
    pub const fn new(routes: &'a [RouteDescriptor]) -> Self {
        Self { routes }
    }
    /// Return every descriptor in declaration order.
    #[must_use]
    pub const fn routes(self) -> &'a [RouteDescriptor] {
        self.routes
    }
    /// Validate uniqueness, grammar, listener boundaries, and projection policy. All violations are
    /// returned in declaration order so CI can report a complete catalog failure in one run.
    ///
    /// # Errors
    ///
    /// Returns every detected [`CatalogValidationError`] when any descriptor
    /// violates the catalog contract.
    pub fn validate(self) -> Result<(), Vec<CatalogValidationError>> {
        validate_catalog(self.routes)
    }
    /// Materialize one consumer projection in declaration order.
    /// Mounted, `OpenAPI`, and MCP projections honor `features`. The SDK
    /// projection is the canonical feature-independent superset.
    #[must_use]
    pub fn project(
        self,
        projection: CatalogProjection,
        features: EnabledFeatures<'_>,
    ) -> Vec<&'a RouteDescriptor> {
        self.routes
            .iter()
            .filter(|route| route.is_in_projection(projection, features))
            .collect()
    }
    /// Materialize declared framework-level CORS OPTIONS behavior.
    /// These entries remain separate from explicit application operations so projections never
    /// accidentally generate SDK or MCP methods for them.
    #[must_use]
    pub fn implicit_routes(self, features: EnabledFeatures<'_>) -> Vec<ImplicitRouteDescriptor> {
        let mut routes = Vec::new();
        let mut cors_paths = BTreeSet::new();
        for route in self
            .routes
            .iter()
            .filter(|route| route.is_in_projection(CatalogProjection::Mounted, features))
        {
            if route.cors_options && cors_paths.insert(route.path) {
                routes.push(ImplicitRouteDescriptor {
                    parent_route_id: route.stable_route_id,
                    path: route.path,
                    kind: ImplicitRouteKind::CorsOptions,
                });
            }
        }
        routes
    }
}
/// One catalog validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatalogValidationError {
    /// Route being validated.
    pub stable_route_id: &'static str,
    /// Machine-readable validation failure.
    pub kind: CatalogValidationErrorKind,
}
/// Machine-readable catalog validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogValidationErrorKind {
    /// The route authentication/admission metadata uses an unsupported schema version.
    UnsupportedAuthMetadataSchemaVersion {
        /// Unsupported version found on the descriptor.
        found: u16,
    },
    /// The stable route ID does not use dot-separated lower-snake-case segments.
    InvalidStableRouteId,
    /// Another descriptor already uses the same stable route ID.
    DuplicateStableRouteId,
    /// Another descriptor already uses the same method and path.
    DuplicateMethodAndPath {
        /// Stable ID of the first descriptor with this method and path.
        existing_route_id: &'static str,
    },
    /// Another descriptor uses the same router shape with different parameter names.
    DuplicateMethodAndShape {
        /// Stable ID of the first descriptor with this method and shape.
        existing_route_id: &'static str,
    },
    /// The path violates its declared grammar policy.
    InvalidPath {
        /// Stable, human-readable reason suitable for CI diagnostics.
        reason: &'static str,
    },
    /// A feature name is not a canonical Cargo feature name.
    InvalidFeatureName {
        /// Invalid feature name.
        feature: &'static str,
    },
    /// An `All` or `Any` feature expression contains no features.
    EmptyFeatureExpression,
    /// Diagnostic routes cannot be projected into SDKs or MCP.
    DiagnosticToolingProjection,
    /// A protocol-handshake route cannot be represented as an ordinary MCP request/response tool.
    ProtocolHandshakeMcpProjection,
    /// Operator-surface routes must enforce an operator authentication policy.
    OperatorSurfaceRequiresAuthentication,
    /// Operator credential exchange is valid only on the operator surface.
    OperatorCredentialExchangeRequiresOperatorSurface,
    /// Target-route admission must use the sealed nested-route authentication boundary.
    TargetRouteAdmissionRequiresNestedAuthentication,
    /// Nested-route authentication is reserved for a protocol gateway whose
    /// exact target owns principal admission.
    NestedAuthenticationRequiresProtocolTargetRoute,
    /// A mutation can never be admitted without an eligible principal.
    PublicMutation,
    /// Attacker-amplifiable computation can never be admitted without an eligible principal.
    PublicExpensiveCompute,
    /// Long-lived transports can never be admitted without an eligible principal.
    PublicLongLivedStream,
    /// An operator audience must require an operator principal.
    OperatorSurfaceRequiresOperatorAdmission,
    /// Account admission lacks a canonical account, manifest, signed-body, or
    /// authenticated streaming boundary.
    AuthenticatedAccountRequiresAuthentication,
    /// Dataspace-selected admission lacks optional or required canonical account authentication.
    DataspaceVisibleRequiresAccountAuthentication,
    /// Non-ledger principal admission lacks a protocol handshake or private-root owner token.
    AuthenticatedProtocolPrincipalRequiresAuthentication,
    /// Validator/roster admission lacks a peer or operator identity boundary.
    ValidatorAdmissionRequiresAuthentication,
    /// Governed-auditor admission lacks an identity-bound signature boundary.
    GovernedAuditorAdmissionRequiresAuthentication,
    /// Operator admission lacks an operator-capable credential boundary.
    OperatorAdmissionRequiresAuthentication,
    /// SSE and WebSocket transports must use GET.
    StreamingTransportRequiresGet,
    /// SSE and WebSocket transports must be classified as long-lived streams.
    StreamingTransportRequiresLongLivedStream,
    /// Long-lived streams must declare either SSE or WebSocket transport.
    LongLivedStreamRequiresStreamingTransport,
    /// Long-lived streams require handler or middleware authentication.
    LongLivedStreamRequiresAuthentication,
    /// Catch-all method routing is reserved for protocol-native gateways.
    AnyMethodRequiresProtocolSurface,
    /// Catch-all method routing cannot be projected into generated tooling.
    AnyMethodToolingProjection,
}
/// Validate a complete route catalog. This function reports all detected violations rather than
/// stopping at the first one. An empty slice is valid so feature-composed catalogs can be checked
/// uniformly.
///
/// # Errors
///
/// Returns every detected [`CatalogValidationError`] when any descriptor
/// violates the catalog contract.
pub fn validate_catalog(routes: &[RouteDescriptor]) -> Result<(), Vec<CatalogValidationError>> {
    let mut errors = Vec::new();
    let mut ids = BTreeSet::new();
    let mut method_paths = BTreeMap::new();
    let mut method_shapes = BTreeMap::new();
    for route in routes {
        let route_id = route.stable_route_id;
        if route.auth_metadata_schema_version != ROUTE_AUTH_METADATA_SCHEMA_VERSION_V1 {
            errors.push(CatalogValidationError {
                stable_route_id: route_id,
                kind: CatalogValidationErrorKind::UnsupportedAuthMetadataSchemaVersion {
                    found: route.auth_metadata_schema_version,
                },
            });
        }
        if !valid_stable_route_id(route_id) {
            errors.push(CatalogValidationError {
                stable_route_id: route_id,
                kind: CatalogValidationErrorKind::InvalidStableRouteId,
            });
        }
        if !ids.insert(route_id) {
            errors.push(CatalogValidationError {
                stable_route_id: route_id,
                kind: CatalogValidationErrorKind::DuplicateStableRouteId,
            });
        }
        let duplicate_exact = method_paths
            .insert((route.method, route.path), route_id)
            .is_some_and(|existing_route_id| {
                errors.push(CatalogValidationError {
                    stable_route_id: route_id,
                    kind: CatalogValidationErrorKind::DuplicateMethodAndPath { existing_route_id },
                });
                true
            });
        let shape = normalized_route_shape(route.path);
        if let Some(existing_route_id) = method_shapes.insert((route.method, shape), route_id)
            && !duplicate_exact
        {
            errors.push(CatalogValidationError {
                stable_route_id: route_id,
                kind: CatalogValidationErrorKind::DuplicateMethodAndShape { existing_route_id },
            });
        }
        if let Err(reason) = validate_path(route) {
            errors.push(CatalogValidationError {
                stable_route_id: route_id,
                kind: CatalogValidationErrorKind::InvalidPath { reason },
            });
        }
        match route.feature_gate {
            FeatureGate::All(names) | FeatureGate::Any(names) if names.is_empty() => {
                errors.push(CatalogValidationError {
                    stable_route_id: route_id,
                    kind: CatalogValidationErrorKind::EmptyFeatureExpression,
                });
            }
            _ => {}
        }
        match route.feature_gate {
            FeatureGate::Always => {}
            FeatureGate::Feature(feature) => {
                validate_feature_name(route_id, feature, &mut errors);
            }
            FeatureGate::All(features) | FeatureGate::Any(features) => {
                for &feature in features {
                    validate_feature_name(route_id, feature, &mut errors);
                }
            }
        }
        if route.surface == ApiSurface::Diagnostic
            && (route.projections.sdk() || route.projections.mcp())
        {
            errors.push(CatalogValidationError {
                stable_route_id: route_id,
                kind: CatalogValidationErrorKind::DiagnosticToolingProjection,
            });
        }
        if route.authentication == AuthenticationPolicy::ProtocolHandshake
            && route.projections.mcp()
        {
            errors.push(CatalogValidationError {
                stable_route_id: route_id,
                kind: CatalogValidationErrorKind::ProtocolHandshakeMcpProjection,
            });
        }
        if route.surface == ApiSurface::Operator
            && !matches!(
                route.authentication,
                AuthenticationPolicy::OperatorSignature
                    | AuthenticationPolicy::OperatorCredentialExchange
            )
            && !(route.stable_route_id == "operator.internal_torii_proxy"
                && route.authentication == AuthenticationPolicy::IdentityBoundSignature)
        {
            errors.push(CatalogValidationError {
                stable_route_id: route_id,
                kind: CatalogValidationErrorKind::OperatorSurfaceRequiresAuthentication,
            });
        }
        if route.authentication == AuthenticationPolicy::OperatorCredentialExchange
            && route.surface != ApiSurface::Operator
        {
            errors.push(CatalogValidationError {
                stable_route_id: route_id,
                kind: CatalogValidationErrorKind::OperatorCredentialExchangeRequiresOperatorSurface,
            });
        }
        if route.admission == AdmissionPolicy::TargetRoute
            && route.authentication != AuthenticationPolicy::NestedRouteAuthentication
        {
            errors.push(CatalogValidationError {
                stable_route_id: route_id,
                kind: CatalogValidationErrorKind::TargetRouteAdmissionRequiresNestedAuthentication,
            });
        }
        if route.authentication == AuthenticationPolicy::NestedRouteAuthentication
            && (route.admission != AdmissionPolicy::TargetRoute
                || route.surface != ApiSurface::Protocol)
        {
            errors.push(CatalogValidationError {
                stable_route_id: route_id,
                kind: CatalogValidationErrorKind::NestedAuthenticationRequiresProtocolTargetRoute,
            });
        }
        match (route.effect, route.admission) {
            (RouteEffect::Mutation, AdmissionPolicy::Public) => {
                errors.push(CatalogValidationError {
                    stable_route_id: route_id,
                    kind: CatalogValidationErrorKind::PublicMutation,
                });
            }
            (RouteEffect::ExpensiveCompute, AdmissionPolicy::Public) => {
                errors.push(CatalogValidationError {
                    stable_route_id: route_id,
                    kind: CatalogValidationErrorKind::PublicExpensiveCompute,
                });
            }
            (RouteEffect::LongLivedStream, AdmissionPolicy::Public) => {
                errors.push(CatalogValidationError {
                    stable_route_id: route_id,
                    kind: CatalogValidationErrorKind::PublicLongLivedStream,
                });
            }
            _ => {}
        }
        if route.surface == ApiSurface::Operator && route.admission != AdmissionPolicy::Operator {
            errors.push(CatalogValidationError {
                stable_route_id: route_id,
                kind: CatalogValidationErrorKind::OperatorSurfaceRequiresOperatorAdmission,
            });
        }
        if route.admission == AdmissionPolicy::AuthenticatedAccount
            && !matches!(
                route.authentication,
                AuthenticationPolicy::CanonicalAccountSignature
                    | AuthenticationPolicy::CanonicalSignedBody
                    | AuthenticationPolicy::ManifestConditionalContent
            )
            && !(route.effect == RouteEffect::LongLivedStream
                && route.authentication == AuthenticationPolicy::ProtocolHandshake)
        {
            errors.push(CatalogValidationError {
                stable_route_id: route_id,
                kind: CatalogValidationErrorKind::AuthenticatedAccountRequiresAuthentication,
            });
        }
        if route.admission == AdmissionPolicy::DataspaceVisible
            && !matches!(
                route.authentication,
                AuthenticationPolicy::OptionalCanonicalAccountSignature
                    | AuthenticationPolicy::CanonicalAccountSignature
            )
        {
            errors.push(CatalogValidationError {
                stable_route_id: route_id,
                kind: CatalogValidationErrorKind::DataspaceVisibleRequiresAccountAuthentication,
            });
        }
        if route.admission == AdmissionPolicy::AuthenticatedProtocolPrincipal
            && !matches!(
                route.authentication,
                AuthenticationPolicy::ProtocolHandshake
                    | AuthenticationPolicy::PrivateRootOwnerToken
            )
        {
            errors.push(CatalogValidationError {
                stable_route_id: route_id,
                kind: CatalogValidationErrorKind::AuthenticatedProtocolPrincipalRequiresAuthentication,
            });
        }
        if route.admission == AdmissionPolicy::ValidatorRosterMember
            && !matches!(
                route.authentication,
                AuthenticationPolicy::ProtocolHandshake
                    | AuthenticationPolicy::IdentityBoundSignature
                    | AuthenticationPolicy::OperatorSignature
            )
        {
            errors.push(CatalogValidationError {
                stable_route_id: route_id,
                kind: CatalogValidationErrorKind::ValidatorAdmissionRequiresAuthentication,
            });
        }
        if route.admission == AdmissionPolicy::GovernedAuditor
            && route.authentication != AuthenticationPolicy::IdentityBoundSignature
        {
            errors.push(CatalogValidationError {
                stable_route_id: route_id,
                kind: CatalogValidationErrorKind::GovernedAuditorAdmissionRequiresAuthentication,
            });
        }
        if route.admission == AdmissionPolicy::Operator
            && !matches!(
                route.authentication,
                AuthenticationPolicy::OnboardingToken
                    | AuthenticationPolicy::IdentityBoundSignature
                    | AuthenticationPolicy::OperatorSignature
                    | AuthenticationPolicy::OperatorCredentialExchange
                    | AuthenticationPolicy::ProtocolHandshake
            )
        {
            errors.push(CatalogValidationError {
                stable_route_id: route_id,
                kind: CatalogValidationErrorKind::OperatorAdmissionRequiresAuthentication,
            });
        }
        if route.transport != RouteTransport::Http {
            if route.method != HttpMethod::Get {
                errors.push(CatalogValidationError {
                    stable_route_id: route_id,
                    kind: CatalogValidationErrorKind::StreamingTransportRequiresGet,
                });
            }
            if route.effect != RouteEffect::LongLivedStream {
                errors.push(CatalogValidationError {
                    stable_route_id: route_id,
                    kind: CatalogValidationErrorKind::StreamingTransportRequiresLongLivedStream,
                });
            }
        }
        if route.effect == RouteEffect::LongLivedStream {
            if route.transport == RouteTransport::Http {
                errors.push(CatalogValidationError {
                    stable_route_id: route_id,
                    kind: CatalogValidationErrorKind::LongLivedStreamRequiresStreamingTransport,
                });
            }
            if matches!(
                route.authentication,
                AuthenticationPolicy::ToriiDefault | AuthenticationPolicy::Unauthenticated
            ) {
                errors.push(CatalogValidationError {
                    stable_route_id: route_id,
                    kind: CatalogValidationErrorKind::LongLivedStreamRequiresAuthentication,
                });
            }
        }
        if route.method == HttpMethod::Any {
            if route.surface != ApiSurface::Protocol {
                errors.push(CatalogValidationError {
                    stable_route_id: route_id,
                    kind: CatalogValidationErrorKind::AnyMethodRequiresProtocolSurface,
                });
            }
            if route.projections != RouteProjections::NONE {
                errors.push(CatalogValidationError {
                    stable_route_id: route_id,
                    kind: CatalogValidationErrorKind::AnyMethodToolingProjection,
                });
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}
fn validate_path(route: &RouteDescriptor) -> Result<(), &'static str> {
    let path = route.path;
    if !path.starts_with('/') {
        return Err("path must begin with a slash");
    }
    if path.len() > 1 && path.ends_with('/') {
        return Err("path must not have a trailing slash");
    }
    if path.contains("//") {
        return Err("path must not contain duplicate slashes");
    }
    if path.contains(['?', '#', '%']) {
        return Err("path must not contain query, fragment, or percent-encoded text");
    }
    if let PathPolicy::ProtocolException { reason } = route.path_policy {
        if reason.trim().is_empty() {
            return Err("protocol exception must include a review rationale");
        }
        return validate_wildcard_shape(path, route.route_match);
    }
    let Some(remaining_path) = path.strip_prefix("/v1/") else {
        return Err("canonical path must begin with /v1/");
    };
    if remaining_path.is_empty() {
        return Err("canonical path must name a resource after /v1");
    }
    let segment_count = remaining_path.split('/').count();
    let mut parameters = BTreeSet::new();
    for (index, segment) in remaining_path.split('/').enumerate() {
        if let Some(parameter) = segment
            .strip_prefix("{*")
            .and_then(|value| value.strip_suffix('}'))
        {
            if route.route_match != RouteMatch::Wildcard || index + 1 != segment_count {
                return Err("wildcard parameter must be declared and appear last");
            }
            if !valid_snake_name(parameter) || !parameters.insert(parameter) {
                return Err("path parameters must be unique lower-snake-case names");
            }
        } else if let Some(parameter) = segment
            .strip_prefix('{')
            .and_then(|value| value.strip_suffix('}'))
        {
            if !valid_snake_name(parameter) || !parameters.insert(parameter) {
                return Err("path parameters must be unique lower-snake-case names");
            }
        } else {
            if !valid_kebab_segment(segment) {
                return Err("static path segments must use lowercase kebab-case");
            }
            if matches!(segment, "get" | "list" | "json" | "sse") {
                return Err("static path segment uses a forbidden transport or CRUD word");
            }
            if segment.strip_prefix('v').is_some_and(|suffix| {
                !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
            }) {
                return Err("nested API-version segment is forbidden");
            }
        }
    }
    validate_wildcard_shape(path, route.route_match)
}
fn validate_wildcard_shape(path: &str, route_match: RouteMatch) -> Result<(), &'static str> {
    let segment_count = path.split('/').count();
    let mut wildcard_count = 0;
    let mut wildcard_is_final = false;
    for (index, segment) in path.split('/').enumerate() {
        if segment.starts_with("{*") && segment.ends_with('}') {
            wildcard_count += 1;
            wildcard_is_final = index + 1 == segment_count;
        }
    }
    match (route_match, wildcard_count) {
        (RouteMatch::Exact, 0) => Ok(()),
        (RouteMatch::Wildcard, 1) if wildcard_is_final => Ok(()),
        (RouteMatch::Wildcard, 1) => Err("wildcard parameter must be the final path segment"),
        (RouteMatch::Exact, _) => Err("exact route must not contain a wildcard parameter"),
        (RouteMatch::Wildcard, 0) => Err("wildcard route must contain a wildcard parameter"),
        (RouteMatch::Wildcard, _) => {
            Err("wildcard route must contain exactly one wildcard parameter")
        }
    }
}
fn valid_stable_route_id(value: &str) -> bool {
    !value.is_empty() && value.split('.').all(valid_snake_name)
}
fn valid_snake_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    let mut previous_underscore = false;
    for byte in bytes {
        if byte == b'_' {
            if previous_underscore {
                return false;
            }
            previous_underscore = true;
        } else if byte.is_ascii_lowercase() || byte.is_ascii_digit() {
            previous_underscore = false;
        } else {
            return false;
        }
    }
    !previous_underscore
}
fn valid_kebab_segment(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return false;
    }
    let mut previous_hyphen = false;
    for byte in bytes {
        if byte == b'-' {
            if previous_hyphen {
                return false;
            }
            previous_hyphen = true;
        } else if byte.is_ascii_lowercase() || byte.is_ascii_digit() {
            previous_hyphen = false;
        } else {
            return false;
        }
    }
    !previous_hyphen
}
fn valid_feature_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}
fn validate_feature_name(
    route_id: &'static str,
    feature: &'static str,
    errors: &mut Vec<CatalogValidationError>,
) {
    if !valid_feature_name(feature) {
        errors.push(CatalogValidationError {
            stable_route_id: route_id,
            kind: CatalogValidationErrorKind::InvalidFeatureName { feature },
        });
    }
}
/// Certified native multisig execution-record publication.
pub mod multisig_execution_evidence {
    use super::{
        AdmissionPolicy, ApiSurface, HttpMethod, Listener, RouteDescriptor, RouteEffect,
        RouteProjections,
    };
    /// Exact account, entrypoint and proposal selector resource.
    pub const PATH: &str = crate::multisig_execution_evidence::MULTISIG_EXECUTION_EVIDENCE_PATH_V1;
    /// Complete native content; finality authority remains independently selected by the reader.
    pub const GET: RouteDescriptor = RouteDescriptor::new(
        "multisig.execution_evidence",
        HttpMethod::Get,
        PATH,
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_projections(RouteProjections::ALL)
    .with_cors_options(true);
    /// Sole route in this fixed publication family.
    pub const ROUTES: &[RouteDescriptor] = &[GET];
}

/// Alias lookup, private evaluation, and recipient-resolution descriptors.
pub mod aliases {
    use super::{
        AdmissionPolicy, ApiSurface, AuthenticationPolicy, FeatureGate, HttpMethod, Listener,
        RouteDescriptor, RouteEffect, RouteProjections,
    };
    const fn public_lookup(stable_route_id: &'static str, path: &'static str) -> RouteDescriptor {
        RouteDescriptor::new(
            stable_route_id,
            HttpMethod::Post,
            path,
            ApiSurface::Public,
            Listener::Torii,
            RouteEffect::ReadOnly,
            AdmissionPolicy::Public,
        )
        .with_feature_gate(FeatureGate::Feature("app_api"))
        .with_projections(RouteProjections::ALL)
        .with_cors_options(true)
    }
    const fn dataspace_lookup(
        stable_route_id: &'static str,
        path: &'static str,
    ) -> RouteDescriptor {
        public_lookup(stable_route_id, path)
            .with_authentication(AuthenticationPolicy::OptionalCanonicalAccountSignature)
            .with_admission(AdmissionPolicy::DataspaceVisible)
    }
    /// Resolve an account alias.
    pub const RESOLVE: RouteDescriptor = dataspace_lookup("aliases.resolve", "/v1/aliases/resolve");
    /// Plan one atomic declarative alias setup transaction.
    pub const SETUP_PLAN: RouteDescriptor =
        public_lookup("aliases.setup_plan", "/v1/aliases/setup/plan")
            .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
            .with_admission(AdmissionPolicy::AuthenticatedAccount);
    /// Plan one guarded absolute-expiry alias lease renewal.
    pub const LEASE_RENEW_PLAN: RouteDescriptor =
        public_lookup("aliases.lease_renew_plan", "/v1/aliases/lease/renew/plan")
            .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
            .with_admission(AdmissionPolicy::AuthenticatedAccount);
    /// Plan one owner-only alias auto-renew configuration CAS.
    pub const AUTO_RENEW_PLAN: RouteDescriptor =
        public_lookup("aliases.auto_renew_plan", "/v1/aliases/auto-renew/plan")
            .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
            .with_admission(AdmissionPolicy::AuthenticatedAccount);
    /// Resolve the deterministic numeric alias index.
    pub const RESOLVE_INDEX: RouteDescriptor =
        dataspace_lookup("aliases.resolve_index", "/v1/aliases/resolve-index")
            .with_authentication(AuthenticationPolicy::CanonicalAccountSignature);
    /// List aliases bound to an account.
    pub const BY_ACCOUNT: RouteDescriptor =
        dataspace_lookup("aliases.by_account", "/v1/aliases/by-account");
    /// Resolve a retail recipient reference.
    pub const RETAIL_RECIPIENT_LOOKUP: RouteDescriptor =
        public_lookup("retail.recipient.lookup", "/v1/retail/recipients/lookup")
            .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
            .with_admission(AdmissionPolicy::AuthenticatedAccount);
    /// Resolve a privacy-minimized retail recipient route.
    pub const RETAIL_RECIPIENT_ROUTE: RouteDescriptor =
        public_lookup("retail.recipient.route", "/v1/retail/recipients/route")
            .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
            .with_admission(AdmissionPolicy::AuthenticatedAccount);
    /// Resolve an asset alias.
    pub const ASSET_RESOLVE: RouteDescriptor =
        public_lookup("assets.alias.resolve", "/v1/assets/aliases/resolve");
    /// Alias routes registered when `app_api` is compiled.
    pub const ROUTES: &[RouteDescriptor] = &[
        SETUP_PLAN,
        LEASE_RENEW_PLAN,
        AUTO_RENEW_PLAN,
        RESOLVE,
        RESOLVE_INDEX,
        BY_ACCOUNT,
        RETAIL_RECIPIENT_LOOKUP,
        RETAIL_RECIPIENT_ROUTE,
        ASSET_RESOLVE,
    ];
}
/// Fee quoting and sponsor-program read descriptors.
pub mod fees {
    use super::{
        AdmissionPolicy, ApiSurface, AuthenticationPolicy, FeatureGate, HttpMethod, Listener,
        RouteDescriptor, RouteEffect, RouteProjections,
    };
    /// Canonical fee quote path.
    pub const QUOTE_PATH: &str = "/v1/fees/quote";
    /// Canonical exact sponsor-program lookup path.
    pub const SPONSOR_PROGRAM_BY_ID_PATH: &str = "/v1/fee-sponsor-programs/by-id";
    /// Canonical exact sponsor-program enrollment lookup path.
    pub const SPONSOR_ENROLLMENT_BY_ID_PATH: &str = "/v1/fee-sponsor-enrollments/by-id";
    const fn account_signed_post(
        stable_route_id: &'static str,
        path: &'static str,
        effect: RouteEffect,
    ) -> RouteDescriptor {
        RouteDescriptor::new(
            stable_route_id,
            HttpMethod::Post,
            path,
            ApiSurface::Public,
            Listener::Torii,
            effect,
            AdmissionPolicy::AuthenticatedAccount,
        )
        .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
        .with_feature_gate(FeatureGate::Feature("app_api"))
        .with_projections(RouteProjections::ALL)
        .with_cors_options(true)
    }
    /// Quote the required signature-bound fee intent for one unsigned payload.
    pub const QUOTE: RouteDescriptor =
        account_signed_post("fees.quote", QUOTE_PATH, RouteEffect::ExpensiveCompute);
    /// Read one exact on-chain sponsor program.
    pub const SPONSOR_PROGRAM_BY_ID: RouteDescriptor = account_signed_post(
        "fee_sponsor_program.by_id",
        SPONSOR_PROGRAM_BY_ID_PATH,
        RouteEffect::ReadOnly,
    );
    /// Read one enrollment as its sponsor or exact delegated program registrar.
    pub const SPONSOR_ENROLLMENT_BY_ID: RouteDescriptor = account_signed_post(
        "fee_sponsor_enrollment.by_id",
        SPONSOR_ENROLLMENT_BY_ID_PATH,
        RouteEffect::ReadOnly,
    );
    /// Canonical first-release fee API catalog.
    pub const ROUTES: &[RouteDescriptor] =
        &[QUOTE, SPONSOR_PROGRAM_BY_ID, SPONSOR_ENROLLMENT_BY_ID];
}
/// Operator `WebAuthn` credential-registration and login descriptors.
pub mod operator_authentication {
    use super::{
        AdmissionPolicy, ApiSurface, AuthenticationPolicy, HttpMethod, Listener, RouteDescriptor,
        RouteEffect, RouteProjections,
    };
    const fn credential_exchange(
        stable_route_id: &'static str,
        path: &'static str,
    ) -> RouteDescriptor {
        RouteDescriptor::new(
            stable_route_id,
            HttpMethod::Post,
            path,
            ApiSurface::Operator,
            Listener::Torii,
            RouteEffect::Mutation,
            AdmissionPolicy::Operator,
        )
        .with_authentication(AuthenticationPolicy::OperatorCredentialExchange)
        .with_projections(RouteProjections::OPENAPI)
        .with_cors_options(true)
    }
    const fn credential_management(
        stable_route_id: &'static str,
        method: HttpMethod,
        path: &'static str,
        effect: RouteEffect,
    ) -> RouteDescriptor {
        RouteDescriptor::new(
            stable_route_id,
            method,
            path,
            ApiSurface::Operator,
            Listener::Torii,
            effect,
            AdmissionPolicy::Operator,
        )
        .with_authentication(AuthenticationPolicy::OperatorSignature)
        .with_projections(RouteProjections::OPENAPI)
        .with_cors_options(true)
    }
    /// Start operator `WebAuthn` credential registration.
    pub const REGISTRATION_OPTIONS: RouteDescriptor = credential_exchange(
        "operator.authentication.registration_options",
        "/v1/operator/auth/registration/options",
    );
    /// Verify and persist an operator `WebAuthn` credential.
    pub const REGISTRATION_VERIFY: RouteDescriptor = credential_exchange(
        "operator.authentication.registration_verify",
        "/v1/operator/auth/registration/verify",
    );
    /// Start an operator `WebAuthn` login challenge.
    pub const LOGIN_OPTIONS: RouteDescriptor = credential_exchange(
        "operator.authentication.login_options",
        "/v1/operator/auth/login/options",
    );
    /// Verify an operator `WebAuthn` login challenge and issue a session.
    pub const LOGIN_VERIFY: RouteDescriptor = credential_exchange(
        "operator.authentication.login_verify",
        "/v1/operator/auth/login/verify",
    );
    /// List enrolled operator `WebAuthn` credentials without exposing verification keys.
    pub const CREDENTIALS: RouteDescriptor = credential_management(
        "operator.authentication.credentials",
        HttpMethod::Get,
        "/v1/operator/auth/credentials",
        RouteEffect::ReadOnly,
    );
    /// Delete one operator `WebAuthn` credential and revoke outstanding auth state.
    pub const CREDENTIAL_DELETE: RouteDescriptor = credential_management(
        "operator.authentication.credential_delete",
        HttpMethod::Delete,
        "/v1/operator/auth/credentials/{credential_id}",
        RouteEffect::Mutation,
    );
    /// Complete operator authentication route family.
    pub const ROUTES: &[RouteDescriptor] = &[
        REGISTRATION_OPTIONS,
        REGISTRATION_VERIFY,
        LOGIN_OPTIONS,
        LOGIN_VERIFY,
        CREDENTIALS,
        CREDENTIAL_DELETE,
    ];
}
/// Core node information and operator configuration descriptors.
pub mod core {
    use super::{
        AdmissionPolicy, ApiSurface, AuthenticationPolicy, FeatureGate, HttpMethod, Listener,
        PathPolicy, RouteDescriptor, RouteEffect, RouteProjections,
    };
    /// Node API/build information.
    pub const API_VERSION: RouteDescriptor = RouteDescriptor::new(
        "core.api_version",
        HttpMethod::Get,
        "/v1/api/version",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_projections(RouteProjections::ALL)
    .with_cors_options(true);
    /// Read the node-local connected-peer snapshot as an authenticated operator.
    pub const PEERS: RouteDescriptor = RouteDescriptor::new(
        "core.peers",
        HttpMethod::Get,
        "/v1/peers",
        ApiSurface::Operator,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Operator,
    )
    .with_authentication(AuthenticationPolicy::OperatorSignature)
    .with_projections(RouteProjections::OPENAPI_AND_SDK);
    /// Orchestrator-compatible liveness probe.
    pub const HEALTH: RouteDescriptor = RouteDescriptor::new(
        "protocol.health",
        HttpMethod::Get,
        "/health",
        ApiSurface::Protocol,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_authentication(AuthenticationPolicy::Unauthenticated)
    .with_projections(RouteProjections::ALL)
    .with_path_policy(PathPolicy::ProtocolException {
        reason: "orchestrator health-probe convention",
    });
    /// Process-only liveness probe. This does not imply protocol readiness.
    pub const LIVEZ: RouteDescriptor = RouteDescriptor::new(
        "protocol.livez",
        HttpMethod::Get,
        "/livez",
        ApiSurface::Protocol,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_authentication(AuthenticationPolicy::Unauthenticated)
    .with_projections(RouteProjections::ALL)
    .with_path_policy(PathPolicy::ProtocolException {
        reason: "orchestrator liveness-probe convention",
    });
    /// Complete node readiness probe, independent of optional application state.
    pub const READYZ: RouteDescriptor = RouteDescriptor::new(
        "protocol.readyz",
        HttpMethod::Get,
        "/readyz",
        ApiSurface::Protocol,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_authentication(AuthenticationPolicy::Unauthenticated)
    .with_projections(RouteProjections::ALL)
    .with_path_policy(PathPolicy::ProtocolException {
        reason: "orchestrator readiness-probe convention",
    });
    /// Read the effective node configuration.
    pub const CONFIGURATION_GET: RouteDescriptor = RouteDescriptor::new(
        "operator.configuration.read",
        HttpMethod::Get,
        "/v1/configuration",
        ApiSurface::Operator,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Operator,
    )
    .with_authentication(AuthenticationPolicy::OperatorSignature)
    .with_projections(RouteProjections::OPENAPI);
    /// Read the current Nexus lane lifecycle commitment.
    pub const NEXUS_LIFECYCLE_GET: RouteDescriptor = RouteDescriptor::new(
        "nexus.lifecycle.read",
        HttpMethod::Get,
        "/v1/nexus/lifecycle",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_cors_options(true);
    /// Read one frozen validator committee attempt and its finality attachments.
    pub const NEXUS_VALIDATOR_COMMITTEE_GET: RouteDescriptor = RouteDescriptor::new(
        "nexus.validator_committee.read",
        HttpMethod::Get,
        "/v1/nexus/validator-committee",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_cors_options(true);
    /// Prepare exact staking monetary inputs without submitting a transaction.
    pub const NEXUS_STAKING_PREPARATION_POST: RouteDescriptor = RouteDescriptor::new(
        "nexus.staking.prepare",
        HttpMethod::Post,
        "/v1/nexus/staking/prepare",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_cors_options(true);
    /// Read newest ledger headers.
    pub const LEDGER_HEADERS: RouteDescriptor = RouteDescriptor::new(
        "ledger.headers",
        HttpMethod::Get,
        "/v1/ledger/headers",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_cors_options(true);
    /// Read a ledger execution-state root with authenticated native Sumeragi finality.
    pub const LEDGER_STATE_ROOT: RouteDescriptor = RouteDescriptor::new(
        "ledger.state_root",
        HttpMethod::Get,
        "/v1/ledger/state/{height}",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_cors_options(true);
    /// Read authenticated native Sumeragi ledger execution-state finality.
    pub const LEDGER_STATE_PROOF: RouteDescriptor = RouteDescriptor::new(
        "ledger.state_proof",
        HttpMethod::Get,
        "/v1/ledger/state-proof/{height}",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_cors_options(true);
    /// Read the exact canonical executed block wire at one finalized height.
    pub const LEDGER_EXECUTED_BLOCK_WIRE: RouteDescriptor = RouteDescriptor::new(
        "ledger.executed_block_wire",
        HttpMethod::Get,
        "/v1/ledger/block/{height}",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::AuthenticatedAccount,
    )
    .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_cors_options(true);
    /// Read a transaction-entry proof from a block.
    pub const LEDGER_BLOCK_PROOF: RouteDescriptor = RouteDescriptor::new(
        "ledger.block_proof",
        HttpMethod::Get,
        "/v1/ledger/block/{height}/proof/{entry_hash}",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::AuthenticatedAccount,
    )
    .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_cors_options(true);
    /// Complete resource-name originals; the handler additionally requires the
    /// native genesis-issued full-ledger read permission.
    pub const RESOURCE_NAMES_STATE: RouteDescriptor = RouteDescriptor::new(
        "ledger.resource_names_state",
        HttpMethod::Get,
        "/v1/ledger/resource-names/{challenge}",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::AuthenticatedAccount,
    )
    .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_cors_options(true);
    /// Scoped account/fee originals for an existing native full-ledger read holder.
    pub const AUTHORITY_ORIGINALS: RouteDescriptor = RouteDescriptor::new(
        "ledger.authority_originals",
        HttpMethod::Post,
        "/v1/ledger/authority-originals",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::AuthenticatedAccount,
    )
    .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_cors_options(true);
    /// Internal peer-to-peer Torii HTTP proxy.
    pub const INTERNAL_PROXY: RouteDescriptor = RouteDescriptor::new(
        "operator.internal_torii_proxy",
        HttpMethod::Post,
        "/v1/internal/torii/proxy",
        ApiSurface::Operator,
        Listener::Torii,
        RouteEffect::Mutation,
        AdmissionPolicy::Operator,
    )
    .with_feature_gate(FeatureGate::Feature("connect"))
    .with_authentication(AuthenticationPolicy::IdentityBoundSignature);
    /// Read exact native marketplace policy and rollout qualification.
    pub const NFT_OFFER_CAPABILITIES: RouteDescriptor = RouteDescriptor::new(
        "nft.offers.capabilities",
        HttpMethod::Get,
        "/v1/nft-offers/capabilities",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_cors_options(true);
    /// Read native exact-price NFT offer state.
    pub const NFT_OFFER_LIST: RouteDescriptor = RouteDescriptor::new(
        "nft.offers.list",
        HttpMethod::Get,
        "/v1/nft-offers",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_cors_options(true);
    /// Read native exact-price NFT offer state.
    pub const NFT_OFFER_GET: RouteDescriptor = RouteDescriptor::new(
        "nft.offers.get",
        HttpMethod::Get,
        "/v1/nft-offers/{offer_id}",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_cors_options(true);
    /// Read native game session state or verifier qualification.
    pub const GAME_CAPABILITIES: RouteDescriptor = RouteDescriptor::new(
        "game.capabilities",
        HttpMethod::Get,
        "/v1/games/capabilities",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_cors_options(true);
    /// Read native game session state or verifier qualification.
    pub const GAME_SESSION_LIST: RouteDescriptor = RouteDescriptor::new(
        "game.sessions.list",
        HttpMethod::Get,
        "/v1/games/sessions",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_cors_options(true);
    /// Read native game session state or verifier qualification.
    pub const GAME_SESSION_GET: RouteDescriptor = RouteDescriptor::new(
        "game.sessions.get",
        HttpMethod::Get,
        "/v1/games/sessions/{session_id}",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_cors_options(true);
    /// Read the VPN client profile.
    pub const VPN_PROFILE: RouteDescriptor = RouteDescriptor::new(
        "vpn.profile",
        HttpMethod::Get,
        "/v1/vpn/profile",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_cors_options(true);
    /// Create a VPN price quote.
    pub const VPN_QUOTE_CREATE: RouteDescriptor = RouteDescriptor::new(
        "vpn.quote.create",
        HttpMethod::Post,
        "/v1/vpn/quotes",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ExpensiveCompute,
        AdmissionPolicy::AuthenticatedAccount,
    )
    .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_cors_options(true);
    /// Create a VPN session.
    pub const VPN_SESSION_CREATE: RouteDescriptor = RouteDescriptor::new(
        "vpn.session.create",
        HttpMethod::Post,
        "/v1/vpn/sessions",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::Mutation,
        AdmissionPolicy::AuthenticatedAccount,
    )
    .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_cors_options(true);
    /// List VPN settlement receipts.
    pub const VPN_RECEIPTS: RouteDescriptor = RouteDescriptor::new(
        "vpn.receipt.list",
        HttpMethod::Get,
        "/v1/vpn/receipts",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::AuthenticatedAccount,
    )
    .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_cors_options(true);
    /// Submit a VPN settlement receipt.
    pub const VPN_RECEIPT_SUBMIT: RouteDescriptor = RouteDescriptor::new(
        "vpn.receipt.submit",
        HttpMethod::Post,
        "/v1/vpn/receipts",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::Mutation,
        AdmissionPolicy::AuthenticatedAccount,
    )
    .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_cors_options(true);
    /// Read one VPN session.
    pub const VPN_SESSION: RouteDescriptor = RouteDescriptor::new(
        "vpn.session.read",
        HttpMethod::Get,
        "/v1/vpn/sessions/{session_id}",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::AuthenticatedAccount,
    )
    .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_cors_options(true);
    /// Read the node's wall-clock sample.
    pub const TIME_NOW: RouteDescriptor = RouteDescriptor::new(
        "time.now",
        HttpMethod::Get,
        "/v1/time/now",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_cors_options(true);
    /// Read node-local time synchronization status as an authenticated operator.
    pub const TIME_STATUS: RouteDescriptor = RouteDescriptor::new(
        "time.status",
        HttpMethod::Get,
        "/v1/time/status",
        ApiSurface::Operator,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Operator,
    )
    .with_authentication(AuthenticationPolicy::OperatorSignature)
    .with_projections(RouteProjections::OPENAPI_AND_SDK);
    /// Read one compact execution-proof verification reference.
    pub const GAME_VERIFICATION_GET: RouteDescriptor = RouteDescriptor::new(
        "game.verifications.get",
        HttpMethod::Get,
        "/v1/games/verifications/{verification_id}",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    );
    /// Core information routes registered by `add_core_info_routes`.
    pub const INFO_ROUTES: &[RouteDescriptor] = &[
        API_VERSION,
        PEERS,
        HEALTH,
        LIVEZ,
        READYZ,
        CONFIGURATION_GET,
        NEXUS_LIFECYCLE_GET,
        NEXUS_VALIDATOR_COMMITTEE_GET,
        NEXUS_STAKING_PREPARATION_POST,
        LEDGER_HEADERS,
        LEDGER_STATE_ROOT,
        LEDGER_STATE_PROOF,
        LEDGER_EXECUTED_BLOCK_WIRE,
        LEDGER_BLOCK_PROOF,
        RESOURCE_NAMES_STATE,
        AUTHORITY_ORIGINALS,
        INTERNAL_PROXY,
        NFT_OFFER_CAPABILITIES,
        NFT_OFFER_LIST,
        NFT_OFFER_GET,
        GAME_CAPABILITIES,
        GAME_SESSION_LIST,
        GAME_SESSION_GET,
        GAME_VERIFICATION_GET,
        VPN_PROFILE,
        VPN_QUOTE_CREATE,
        VPN_SESSION_CREATE,
        VPN_RECEIPTS,
        VPN_RECEIPT_SUBMIT,
        VPN_SESSION,
    ];
    /// Time routes registered by `add_time_routes`.
    pub const TIME_ROUTES: &[RouteDescriptor] = &[TIME_NOW, TIME_STATUS];
}
/// Diagnostic and self-description protocol exceptions.
pub mod diagnostic {
    use super::{
        AdmissionPolicy, ApiSurface, AuthenticationPolicy, FeatureGate, HttpMethod, Listener,
        PathPolicy, RouteDescriptor, RouteEffect, RouteProjections,
    };
    /// Root diagnostic status document.
    pub const STATUS: RouteDescriptor = RouteDescriptor::new(
        "diagnostic.status",
        HttpMethod::Get,
        "/status",
        ApiSurface::Diagnostic,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_feature_gate(FeatureGate::Feature("telemetry"))
    .with_authentication(AuthenticationPolicy::Unauthenticated)
    .with_projections(RouteProjections::OPENAPI)
    .with_path_policy(PathPolicy::ProtocolException {
        reason: "established infrastructure status endpoint",
    });
    /// Canonical committed block-height diagnostic.
    pub const STATUS_BLOCKS: RouteDescriptor = RouteDescriptor::new(
        "diagnostic.status_blocks",
        HttpMethod::Get,
        "/status/blocks",
        ApiSurface::Diagnostic,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_feature_gate(FeatureGate::Feature("telemetry"))
    .with_authentication(AuthenticationPolicy::Unauthenticated)
    .with_projections(RouteProjections::OPENAPI)
    .with_path_policy(PathPolicy::ProtocolException {
        reason: "established infrastructure block-height probe",
    });
    /// Current online-peer-count diagnostic.
    pub const STATUS_PEERS: RouteDescriptor = RouteDescriptor::new(
        "diagnostic.status_peers",
        HttpMethod::Get,
        "/status/peers",
        ApiSurface::Diagnostic,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_feature_gate(FeatureGate::Feature("telemetry"))
    .with_authentication(AuthenticationPolicy::Unauthenticated)
    .with_projections(RouteProjections::OPENAPI)
    .with_path_policy(PathPolicy::ProtocolException {
        reason: "established infrastructure peer-count probe",
    });
    /// Prometheus metrics exposition.
    pub const METRICS: RouteDescriptor = RouteDescriptor::new(
        "diagnostic.metrics",
        HttpMethod::Get,
        "/metrics",
        ApiSurface::Diagnostic,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_feature_gate(FeatureGate::Feature("telemetry"))
    .with_authentication(AuthenticationPolicy::Unauthenticated)
    .with_projections(RouteProjections::OPENAPI)
    .with_path_policy(PathPolicy::ProtocolException {
        reason: "Prometheus exposition convention",
    });
    /// CPU profiling capture.
    pub const PROFILE: RouteDescriptor = RouteDescriptor::new(
        "diagnostic.cpu_profile",
        HttpMethod::Get,
        "/debug/pprof/profile",
        ApiSurface::Diagnostic,
        Listener::Torii,
        RouteEffect::ExpensiveCompute,
        AdmissionPolicy::Operator,
    )
    .with_feature_gate(FeatureGate::Feature("profiling"))
    .with_authentication(AuthenticationPolicy::OperatorSignature)
    .with_projections(RouteProjections::OPENAPI)
    .with_path_policy(PathPolicy::ProtocolException {
        reason: "pprof tooling convention",
    });
    /// Runtime schema document.
    pub const SCHEMA: RouteDescriptor = RouteDescriptor::new(
        "protocol.schema",
        HttpMethod::Get,
        "/v1/schema",
        ApiSurface::Protocol,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_feature_gate(FeatureGate::Feature("schema"))
    .with_projections(RouteProjections::OPENAPI);
    /// `OpenAPI` document at its media-typed filename.
    pub const OPENAPI_JSON: RouteDescriptor = RouteDescriptor::new(
        "protocol.openapi_json",
        HttpMethod::Get,
        "/openapi.json",
        ApiSurface::Protocol,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_projections(RouteProjections::OPENAPI)
    .with_path_policy(PathPolicy::ProtocolException {
        reason: "OpenAPI document discovery convention",
    });

    /// Diagnostic and self-description routes registered by the builder.
    pub const ROUTES: &[RouteDescriptor] = &[
        STATUS,
        STATUS_BLOCKS,
        STATUS_PEERS,
        METRICS,
        PROFILE,
        SCHEMA,
        OPENAPI_JSON,
    ];
}
/// Transaction, query, proof, and pipeline routes.
pub mod pipeline {
    use super::{
        AdmissionPolicy, ApiSurface, AuthenticationPolicy, FeatureGate, HttpMethod, Listener,
        RouteDescriptor, RouteEffect, RouteProjections,
    };
    /// Submit one signed transaction.
    pub const TRANSACTION: RouteDescriptor = RouteDescriptor::new(
        "pipeline.transaction.submit",
        HttpMethod::Post,
        "/v1/pipeline/transactions",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::Mutation,
        AdmissionPolicy::AuthenticatedAccount,
    )
    .with_authentication(AuthenticationPolicy::CanonicalSignedBody)
    .with_projections(RouteProjections::ALL)
    .with_cors_options(true);
    /// Submit a transaction entrypoint envelope.
    pub const TRANSACTION_ENTRYPOINT: RouteDescriptor = RouteDescriptor::new(
        "pipeline.transaction_entrypoint.submit",
        HttpMethod::Post,
        "/v1/pipeline/transaction-entrypoints",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::Mutation,
        AdmissionPolicy::AuthenticatedAccount,
    )
    .with_authentication(AuthenticationPolicy::CanonicalSignedBody)
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_cors_options(true);
    /// Submit a batch of signed transactions.
    pub const TRANSACTIONS_BATCH: RouteDescriptor = RouteDescriptor::new(
        "pipeline.transaction_batch.submit",
        HttpMethod::Post,
        "/v1/pipeline/transactions/batch",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::Mutation,
        AdmissionPolicy::AuthenticatedAccount,
    )
    .with_authentication(AuthenticationPolicy::CanonicalSignedBody)
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_cors_options(true);
    /// Execute a signed query.
    pub const QUERY: RouteDescriptor = RouteDescriptor::new(
        "query.execute",
        HttpMethod::Post,
        "/v1/query",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ExpensiveCompute,
        AdmissionPolicy::AuthenticatedAccount,
    )
    .with_authentication(AuthenticationPolicy::CanonicalSignedBody)
    .with_projections(RouteProjections::ALL)
    .with_cors_options(true);
    /// Read one proof record.
    pub const PROOF: RouteDescriptor = RouteDescriptor::new(
        "proof.read",
        HttpMethod::Get,
        "/v1/proofs/{id}",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_feature_gate(FeatureGate::Feature("app_api"))
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_cors_options(true);
    /// Read node-local proof-retention state as an authenticated operator.
    pub const PROOF_RETENTION: RouteDescriptor = RouteDescriptor::new(
        "proof.retention",
        HttpMethod::Get,
        "/v1/proofs/retention",
        ApiSurface::Operator,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Operator,
    )
    .with_authentication(AuthenticationPolicy::OperatorSignature)
    .with_projections(RouteProjections::OPENAPI_AND_SDK);
    /// Read the status of a submitted pipeline transaction.
    pub const TRANSACTION_STATUS: RouteDescriptor = RouteDescriptor::new(
        "pipeline.transaction_status",
        HttpMethod::Get,
        "/v1/pipeline/transactions/status",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_cors_options(true);
    /// Read exact committed transaction details through a one-shot signed query.
    pub const TRANSACTION_DETAILS: RouteDescriptor = RouteDescriptor::new(
        "pipeline.transaction_details",
        HttpMethod::Post,
        "/v1/pipeline/transactions/details",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ExpensiveCompute,
        AdmissionPolicy::AuthenticatedAccount,
    )
    .with_authentication(AuthenticationPolicy::CanonicalSignedBody)
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_cors_options(true);
    /// Read node-local pipeline admission readiness as an authenticated operator.
    pub const PREFLIGHT: RouteDescriptor = RouteDescriptor::new(
        "pipeline.preflight",
        HttpMethod::Get,
        "/v1/pipeline/preflight",
        ApiSurface::Operator,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Operator,
    )
    .with_authentication(AuthenticationPolicy::OperatorSignature)
    .with_projections(RouteProjections::OPENAPI_AND_SDK);
    /// List trigger completion records.
    pub const TRIGGER_COMPLETIONS: RouteDescriptor = RouteDescriptor::new(
        "trigger.completion.list",
        HttpMethod::Get,
        "/v1/triggers/completed",
        ApiSurface::Operator,
        Listener::Torii,
        RouteEffect::ExpensiveCompute,
        AdmissionPolicy::Operator,
    )
    .with_authentication(AuthenticationPolicy::OperatorSignature)
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_cors_options(true);
    /// Read node-local recovery information for one height as an authenticated operator.
    pub const RECOVERY: RouteDescriptor = RouteDescriptor::new(
        "pipeline.recovery",
        HttpMethod::Get,
        "/v1/pipeline/recovery/{height}",
        ApiSurface::Operator,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Operator,
    )
    .with_authentication(AuthenticationPolicy::OperatorSignature)
    .with_projections(RouteProjections::OPENAPI_AND_SDK);
    /// Read `FastPQ` proofs associated with one recovery height.
    pub const RECOVERY_FASTPQ_PROOFS: RouteDescriptor = RouteDescriptor::new(
        "pipeline.recovery_fastpq_proofs",
        HttpMethod::Get,
        "/v1/pipeline/recovery/{height}/fastpq-proofs",
        ApiSurface::Operator,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Operator,
    )
    .with_authentication(AuthenticationPolicy::OperatorSignature)
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_cors_options(true);
    /// Read the effective node-local policy document as an authenticated operator.
    pub const POLICY: RouteDescriptor = RouteDescriptor::new(
        "policy.read",
        HttpMethod::Get,
        "/v1/policy",
        ApiSurface::Operator,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Operator,
    )
    .with_authentication(AuthenticationPolicy::OperatorSignature)
    .with_projections(RouteProjections::OPENAPI_AND_SDK);
    /// Pipeline routes currently registered through the authoritative builder.
    pub const ROUTES: &[RouteDescriptor] = &[
        TRANSACTION,
        TRANSACTION_ENTRYPOINT,
        TRANSACTIONS_BATCH,
        QUERY,
        PROOF,
        PROOF_RETENTION,
        TRANSACTION_STATUS,
        TRANSACTION_DETAILS,
        PREFLIGHT,
        TRIGGER_COMPLETIONS,
        RECOVERY,
        RECOVERY_FASTPQ_PROOFS,
        POLICY,
    ];
}
/// ISO 20022 bridge submission, record, audit, and XML-view descriptors.
pub mod iso20022 {
    use super::{
        AdmissionPolicy, ApiSurface, AuthenticationPolicy, HttpMethod, Listener, RouteDescriptor,
        RouteEffect, RouteProjections,
    };
    const fn public_post(stable_route_id: &'static str, path: &'static str) -> RouteDescriptor {
        RouteDescriptor::new(
            stable_route_id,
            HttpMethod::Post,
            path,
            ApiSurface::Public,
            Listener::Torii,
            RouteEffect::Mutation,
            AdmissionPolicy::Operator,
        )
        .with_authentication(AuthenticationPolicy::OperatorSignature)
        .with_projections(RouteProjections::ALL)
        .with_cors_options(true)
    }
    const fn public_get(stable_route_id: &'static str, path: &'static str) -> RouteDescriptor {
        RouteDescriptor::new(
            stable_route_id,
            HttpMethod::Get,
            path,
            ApiSurface::Public,
            Listener::Torii,
            RouteEffect::ReadOnly,
            AdmissionPolicy::Operator,
        )
        .with_authentication(AuthenticationPolicy::OperatorSignature)
        .with_projections(RouteProjections::ALL)
        .with_cors_options(true)
    }
    /// Submit a pacs.008 customer-credit-transfer message.
    pub const PACS008_SUBMIT: RouteDescriptor =
        public_post("iso20022.pacs008.submit", "/v1/iso20022/pacs008");
    /// Submit a pacs.009 financial-institution-transfer message.
    pub const PACS009_SUBMIT: RouteDescriptor =
        public_post("iso20022.pacs009.submit", "/v1/iso20022/pacs009");
    /// Submit a pacs.002 lifecycle message.
    pub const PACS002_SUBMIT: RouteDescriptor =
        public_post("iso20022.pacs002.submit", "/v1/iso20022/pacs002");
    /// Submit a pacs.004 lifecycle message.
    pub const PACS004_SUBMIT: RouteDescriptor =
        public_post("iso20022.pacs004.submit", "/v1/iso20022/pacs004");
    /// Submit a camt.056 lifecycle message.
    pub const CAMT056_SUBMIT: RouteDescriptor =
        public_post("iso20022.camt056.submit", "/v1/iso20022/camt056");
    /// Submit a sese.023 settlement-instruction message.
    pub const SESE023_SUBMIT: RouteDescriptor =
        public_post("iso20022.sese023.submit", "/v1/iso20022/sese023");
    /// Submit a sese.024 settlement-status message.
    pub const SESE024_SUBMIT: RouteDescriptor =
        public_post("iso20022.sese024.submit", "/v1/iso20022/sese024");
    /// Submit a sese.025 settlement-confirmation message.
    pub const SESE025_SUBMIT: RouteDescriptor =
        public_post("iso20022.sese025.submit", "/v1/iso20022/sese025");
    /// Submit a colr.012 collateral-substitution message.
    pub const COLR012_SUBMIT: RouteDescriptor =
        public_post("iso20022.colr012.submit", "/v1/iso20022/colr012");
    /// Read the canonical rich record for one ISO 20022 message.
    pub const MESSAGE: RouteDescriptor =
        public_get("iso20022.message.read", "/v1/iso20022/messages/{msg_id}");
    /// Read the tamper-evident ISO 20022 audit manifest.
    pub const AUDIT_MESSAGES: RouteDescriptor =
        public_get("iso20022.audit.read", "/v1/iso20022/audit/messages");
    /// Render the current pacs.002 XML for one message.
    pub const MESSAGE_PACS002: RouteDescriptor = public_get(
        "iso20022.message.pacs002",
        "/v1/iso20022/messages/{msg_id}/pacs002",
    );
    /// Render the current pacs.004 XML for one message.
    pub const MESSAGE_PACS004: RouteDescriptor = public_get(
        "iso20022.message.pacs004",
        "/v1/iso20022/messages/{msg_id}/pacs004",
    );
    /// Render the current camt.029 XML for one message.
    pub const MESSAGE_CAMT029: RouteDescriptor = public_get(
        "iso20022.message.camt029",
        "/v1/iso20022/messages/{msg_id}/camt029",
    );
    /// Render the current sese.024 XML for one message.
    pub const MESSAGE_SESE024: RouteDescriptor = public_get(
        "iso20022.message.sese024",
        "/v1/iso20022/messages/{msg_id}/sese024",
    );
    /// Render the current sese.025 XML for one message.
    pub const MESSAGE_SESE025: RouteDescriptor = public_get(
        "iso20022.message.sese025",
        "/v1/iso20022/messages/{msg_id}/sese025",
    );
    /// Complete first-release ISO 20022 route family.
    pub const ROUTES: &[RouteDescriptor] = &[
        PACS008_SUBMIT,
        PACS009_SUBMIT,
        PACS002_SUBMIT,
        PACS004_SUBMIT,
        CAMT056_SUBMIT,
        SESE023_SUBMIT,
        SESE024_SUBMIT,
        SESE025_SUBMIT,
        COLR012_SUBMIT,
        MESSAGE,
        AUDIT_MESSAGES,
        MESSAGE_PACS002,
        MESSAGE_PACS004,
        MESSAGE_CAMT029,
        MESSAGE_SESE024,
        MESSAGE_SESE025,
    ];
}
/// Data-availability ingestion, proof-policy, commitment, and pin descriptors.
pub mod data_availability {
    use super::{
        AdmissionPolicy, ApiSurface, AuthenticationPolicy, FeatureGate, HttpMethod, Listener,
        RouteDescriptor, RouteEffect, RouteProjections,
    };
    const fn public_post(stable_route_id: &'static str, path: &'static str) -> RouteDescriptor {
        RouteDescriptor::new(
            stable_route_id,
            HttpMethod::Post,
            path,
            ApiSurface::Public,
            Listener::Torii,
            RouteEffect::ReadOnly,
            AdmissionPolicy::Public,
        )
        .with_projections(RouteProjections::ALL)
        .with_cors_options(true)
    }
    const fn public_get(stable_route_id: &'static str, path: &'static str) -> RouteDescriptor {
        RouteDescriptor::new(
            stable_route_id,
            HttpMethod::Get,
            path,
            ApiSurface::Public,
            Listener::Torii,
            RouteEffect::ReadOnly,
            AdmissionPolicy::Public,
        )
        .with_projections(RouteProjections::ALL)
        .with_cors_options(true)
    }
    /// Ingest a data-availability blob and routing manifest.
    pub const INGEST: RouteDescriptor = public_post("data_availability.ingest", "/v1/da/ingest")
        .with_feature_gate(FeatureGate::Feature("app_api"))
        .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
        .with_effect(RouteEffect::Mutation)
        .with_admission(AdmissionPolicy::AuthenticatedAccount);
    /// Read the manifest addressed by a storage ticket.
    pub const MANIFEST: RouteDescriptor = public_get(
        "data_availability.manifest.read",
        "/v1/da/manifests/{ticket}",
    )
    .with_feature_gate(FeatureGate::Feature("app_api"));
    /// List supported data-availability proof policies.
    pub const PROOF_POLICIES: RouteDescriptor = public_get(
        "data_availability.proof_policy.list",
        "/v1/da/proof-policies",
    );
    /// List commitments selected by a typed filter request.
    pub const COMMITMENTS: RouteDescriptor =
        public_post("data_availability.commitment.list", "/v1/da/commitments");
    /// Produce a proof for a data-availability commitment.
    pub const COMMITMENTS_PROVE: RouteDescriptor = public_post(
        "data_availability.commitment.prove",
        "/v1/da/commitments/prove",
    )
    .with_effect(RouteEffect::ExpensiveCompute)
    .with_admission(AdmissionPolicy::AuthenticatedAccount)
    .with_authentication(AuthenticationPolicy::CanonicalAccountSignature);
    /// Verify a proof for a data-availability commitment.
    pub const COMMITMENTS_VERIFY: RouteDescriptor = public_post(
        "data_availability.commitment.verify",
        "/v1/da/commitments/verify",
    )
    .with_effect(RouteEffect::ExpensiveCompute)
    .with_admission(AdmissionPolicy::AuthenticatedAccount)
    .with_authentication(AuthenticationPolicy::CanonicalAccountSignature);
    /// List pin intents selected by a typed filter request.
    pub const PIN_INTENTS: RouteDescriptor =
        public_post("data_availability.pin_intent.list", "/v1/da/pin-intents");
    /// Produce a proof for a pin intent.
    pub const PIN_INTENTS_PROVE: RouteDescriptor = public_post(
        "data_availability.pin_intent.prove",
        "/v1/da/pin-intents/prove",
    )
    .with_effect(RouteEffect::ExpensiveCompute)
    .with_admission(AdmissionPolicy::AuthenticatedAccount)
    .with_authentication(AuthenticationPolicy::CanonicalAccountSignature);
    /// Verify a proof for a pin intent.
    pub const PIN_INTENTS_VERIFY: RouteDescriptor = public_post(
        "data_availability.pin_intent.verify",
        "/v1/da/pin-intents/verify",
    )
    .with_effect(RouteEffect::ExpensiveCompute)
    .with_admission(AdmissionPolicy::AuthenticatedAccount)
    .with_authentication(AuthenticationPolicy::CanonicalAccountSignature);
    /// Complete data-availability route family.
    pub const ROUTES: &[RouteDescriptor] = &[
        INGEST,
        MANIFEST,
        PROOF_POLICIES,
        COMMITMENTS,
        COMMITMENTS_PROVE,
        COMMITMENTS_VERIFY,
        PIN_INTENTS,
        PIN_INTENTS_PROVE,
        PIN_INTENTS_VERIFY,
    ];
}
/// First-release Musubi typed-query and unsigned-instruction descriptors.
#[path = "route_catalog/musubi.rs"]
pub mod musubi;
/// Atomic private cross-dataspace settlement endpoints.
#[path = "route_catalog/private_settlement.rs"]
pub mod private_settlement;
/// Protocol-native event and peer transports.
pub mod streaming {
    use super::{
        AdmissionPolicy, ApiSurface, AuthenticationPolicy, FeatureGate, HttpMethod, Listener,
        PathPolicy, RouteDescriptor, RouteEffect, RouteProjections, RouteTransport,
    };
    /// SSE event stream.
    pub const EVENTS_SSE: RouteDescriptor = RouteDescriptor::new(
        "events.stream_sse",
        HttpMethod::Get,
        "/v1/events/sse",
        ApiSurface::Protocol,
        Listener::Torii,
        RouteEffect::LongLivedStream,
        AdmissionPolicy::DataspaceVisible,
    )
    .with_feature_gate(FeatureGate::Feature("app_api"))
    .with_authentication(AuthenticationPolicy::OptionalCanonicalAccountSignature)
    .with_transport(RouteTransport::ServerSentEvents)
    .with_projections(RouteProjections::OPENAPI)
    .with_path_policy(PathPolicy::ProtocolException {
        reason: "SSE transport endpoint; stream contract is not an ordinary resource",
    });
    /// Call-derived contract-event SSE stream.
    ///
    /// Rows are projected from committed top-level `ContractCall` transactions and
    /// the metadata consensus bound to them; contracts emit none of them, and
    /// `provenance` is always `derived`.
    pub const CONTRACT_EVENTS_SSE: RouteDescriptor = RouteDescriptor::new(
        "contracts.events_stream_sse",
        HttpMethod::Get,
        "/v1/contracts/events/sse",
        ApiSurface::Protocol,
        Listener::Torii,
        RouteEffect::LongLivedStream,
        AdmissionPolicy::DataspaceVisible,
    )
    .with_feature_gate(FeatureGate::Feature("app_api"))
    .with_authentication(AuthenticationPolicy::OptionalCanonicalAccountSignature)
    .with_transport(RouteTransport::ServerSentEvents)
    .with_projections(RouteProjections::OPENAPI)
    .with_path_policy(PathPolicy::ProtocolException {
        reason: "SSE transport endpoint; stream contract is not an ordinary resource",
    });
    /// Event subscription WebSocket.
    pub const SUBSCRIPTION_WS: RouteDescriptor = RouteDescriptor::new(
        "events.stream_websocket",
        HttpMethod::Get,
        "/v1/events/ws",
        ApiSurface::Protocol,
        Listener::Torii,
        RouteEffect::LongLivedStream,
        AdmissionPolicy::DataspaceVisible,
    )
    .with_feature_gate(FeatureGate::Feature("app_api"))
    .with_authentication(AuthenticationPolicy::OptionalCanonicalAccountSignature)
    .with_transport(RouteTransport::WebSocket)
    .with_projections(RouteProjections::OPENAPI)
    .with_path_policy(PathPolicy::ProtocolException {
        reason: "WebSocket transport endpoint",
    });
    /// Block stream WebSocket.
    pub const BLOCKS_WS: RouteDescriptor = RouteDescriptor::new(
        "blocks.stream_websocket",
        HttpMethod::Get,
        "/v1/blocks/stream",
        ApiSurface::Protocol,
        Listener::Torii,
        RouteEffect::LongLivedStream,
        AdmissionPolicy::AuthenticatedAccount,
    )
    .with_feature_gate(FeatureGate::Feature("app_api"))
    .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
    .with_transport(RouteTransport::WebSocket)
    .with_projections(RouteProjections::OPENAPI)
    .with_path_policy(PathPolicy::ProtocolException {
        reason: "WebSocket transport endpoint",
    });
    /// Application streaming routes registered when `app_api` is compiled.
    pub const APP_ROUTES: &[RouteDescriptor] =
        &[EVENTS_SSE, CONTRACT_EVENTS_SSE, SUBSCRIPTION_WS, BLOCKS_WS];
}
/// Iroha Connect pairing and relay routes.
#[path = "route_catalog/connect.rs"]
pub mod connect;
/// Native MCP transport routes.
#[path = "route_catalog/mcp_transport.rs"]
pub mod mcp_transport;
/// Telemetry-gated operator diagnostics, privacy ingestion, and asset-holder routes.
pub mod telemetry {
    use super::{
        AdmissionPolicy, ApiSurface, AuthenticationPolicy, FeatureGate, HttpMethod, Listener,
        RouteDescriptor, RouteEffect, RouteProjections,
    };
    const fn telemetry_operator_get(id: &'static str, path: &'static str) -> RouteDescriptor {
        RouteDescriptor::new(
            id,
            HttpMethod::Get,
            path,
            ApiSurface::Operator,
            Listener::Torii,
            RouteEffect::ReadOnly,
            AdmissionPolicy::Operator,
        )
        .with_authentication(AuthenticationPolicy::OperatorSignature)
        .with_feature_gate(FeatureGate::Feature("telemetry"))
        .with_projections(RouteProjections::ALL)
    }
    const fn telemetry_collector_post(id: &'static str, path: &'static str) -> RouteDescriptor {
        RouteDescriptor::new(
            id,
            HttpMethod::Post,
            path,
            ApiSurface::Public,
            Listener::Torii,
            RouteEffect::Mutation,
            AdmissionPolicy::Operator,
        )
        .with_authentication(AuthenticationPolicy::OperatorSignature)
        .with_feature_gate(FeatureGate::Feature("telemetry"))
        .with_projections(RouteProjections::OPENAPI_AND_SDK)
        .with_cors_options(true)
    }
    const fn app_get(id: &'static str, path: &'static str) -> RouteDescriptor {
        RouteDescriptor::new(
            id,
            HttpMethod::Get,
            path,
            ApiSurface::Public,
            Listener::Torii,
            RouteEffect::ReadOnly,
            AdmissionPolicy::Public,
        )
        .with_feature_gate(FeatureGate::Feature("app_api"))
        .with_projections(RouteProjections::ALL)
        .with_cors_options(true)
    }
    const fn app_post(id: &'static str, path: &'static str) -> RouteDescriptor {
        RouteDescriptor::new(
            id,
            HttpMethod::Post,
            path,
            ApiSurface::Public,
            Listener::Torii,
            RouteEffect::ExpensiveCompute,
            AdmissionPolicy::AuthenticatedAccount,
        )
        .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
        .with_feature_gate(FeatureGate::Feature("app_api"))
        .with_projections(RouteProjections::ALL)
        .with_cors_options(true)
    }
    /// Read the atomic cross-transaction cache diagnostic.
    pub const DEBUG_AXT_CACHE: RouteDescriptor =
        telemetry_operator_get("operator.debug.axt_cache", "/v1/debug/axt/cache")
            .with_projections(RouteProjections::OPENAPI);
    /// Read the consensus witness diagnostic.
    pub const DEBUG_WITNESS: RouteDescriptor =
        telemetry_operator_get("operator.debug.witness", "/v1/debug/witness")
            .with_projections(RouteProjections::NONE);
    /// Ingest one `SoraNet` privacy observation.
    pub const SORANET_PRIVACY_EVENT: RouteDescriptor =
        telemetry_collector_post("soranet.privacy_event.ingest", "/v1/soranet/privacy/event");
    /// Ingest one `SoraNet` privacy collector share.
    pub const SORANET_PRIVACY_SHARE: RouteDescriptor =
        telemetry_collector_post("soranet.privacy_share.ingest", "/v1/soranet/privacy/share");
    /// List holders of one asset definition.
    pub const ASSET_HOLDERS: RouteDescriptor =
        app_get("asset.holder.list", "/v1/assets/{definition_id}/holders")
            .with_admission(AdmissionPolicy::DataspaceVisible)
            .with_authentication(AuthenticationPolicy::OptionalCanonicalAccountSignature);
    /// Query holders of one asset definition with a typed request body.
    pub const ASSET_HOLDERS_QUERY: RouteDescriptor = app_post(
        "asset.holder.query",
        "/v1/assets/{definition_id}/holders/query",
    )
    .with_effect(RouteEffect::ReadOnly)
    .with_admission(AdmissionPolicy::DataspaceVisible)
    .with_authentication(AuthenticationPolicy::OptionalCanonicalAccountSignature);
    /// Complete route family registered by `add_telemetry_routes`.
    pub const ROUTES: &[RouteDescriptor] = &[
        DEBUG_AXT_CACHE,
        DEBUG_WITNESS,
        SORANET_PRIVACY_EVENT,
        SORANET_PRIVACY_SHARE,
        ASSET_HOLDERS,
        ASSET_HOLDERS_QUERY,
    ];
}
/// Consensus evidence, bridge finality, and Sumeragi introspection routes.
pub mod sumeragi {
    use super::{
        AdmissionPolicy, ApiSurface, AuthenticationPolicy, FeatureGate, HttpMethod, Listener,
        PathPolicy, RouteDescriptor, RouteEffect, RouteProjections, RouteTransport,
    };
    const fn public_get(id: &'static str, path: &'static str) -> RouteDescriptor {
        RouteDescriptor::new(
            id,
            HttpMethod::Get,
            path,
            ApiSurface::Public,
            Listener::Torii,
            RouteEffect::ReadOnly,
            AdmissionPolicy::Public,
        )
        .with_projections(RouteProjections::ALL)
        .with_cors_options(true)
    }
    const fn operator_get(id: &'static str, path: &'static str) -> RouteDescriptor {
        RouteDescriptor::new(
            id,
            HttpMethod::Get,
            path,
            ApiSurface::Operator,
            Listener::Torii,
            RouteEffect::ReadOnly,
            AdmissionPolicy::Operator,
        )
        .with_authentication(AuthenticationPolicy::OperatorSignature)
        .with_projections(RouteProjections::OPENAPI_AND_SDK)
        .with_cors_options(true)
    }
    const fn telemetry_operator_get(id: &'static str, path: &'static str) -> RouteDescriptor {
        operator_get(id, path).with_feature_gate(FeatureGate::Feature("telemetry"))
    }
    const fn telemetry_sse(id: &'static str, path: &'static str) -> RouteDescriptor {
        RouteDescriptor::new(
            id,
            HttpMethod::Get,
            path,
            ApiSurface::Operator,
            Listener::Torii,
            RouteEffect::LongLivedStream,
            AdmissionPolicy::Operator,
        )
        .with_authentication(AuthenticationPolicy::OperatorSignature)
        .with_transport(RouteTransport::ServerSentEvents)
        .with_feature_gate(FeatureGate::Feature("telemetry"))
        .with_projections(RouteProjections::OPENAPI)
        .with_path_policy(PathPolicy::ProtocolException {
            reason: "SSE transport endpoint; stream contract is not an ordinary resource",
        })
    }
    /// Count persisted consensus evidence records as an authenticated operator.
    pub const EVIDENCE_COUNT: RouteDescriptor =
        operator_get("sumeragi.evidence.count", "/v1/sumeragi/evidence/count");
    /// List persisted consensus evidence records as an authenticated operator.
    pub const EVIDENCE_LIST: RouteDescriptor =
        operator_get("sumeragi.evidence.list", "/v1/sumeragi/evidence");
    /// Read the authoritative Sumeragi status snapshot as an authenticated operator.
    pub const STATUS: RouteDescriptor =
        telemetry_operator_get("sumeragi.status.read", "/v1/sumeragi/status");
    /// Read non-authoritative Sumeragi operator and lane diagnostics as an authenticated operator.
    pub const DIAGNOSTICS: RouteDescriptor =
        telemetry_operator_get("sumeragi.diagnostics.read", "/v1/sumeragi/diagnostics");
    /// Stream authoritative Sumeragi status snapshots as an authenticated operator.
    pub const STATUS_SSE: RouteDescriptor =
        telemetry_sse("sumeragi.status.stream_sse", "/v1/sumeragi/status/sse");
    /// Read the global chain's lanes and the node's lane instances as an authenticated operator.
    pub const LANES: RouteDescriptor =
        telemetry_operator_get("sumeragi.lane.list", "/v1/sumeragi/lanes");
    /// Read the consensus BLS key roster as an authenticated operator.
    pub const BLS_KEYS: RouteDescriptor =
        telemetry_operator_get("sumeragi.bls_key.list", "/v1/sumeragi/bls-keys");
    /// Read an exact active dataspace lease projection at a caller-selected native World cut.
    pub const SNS_DATASPACE_LEASE: RouteDescriptor = public_get(
        "sns.dataspace_lease.read",
        "/v1/sns/dataspaces/{alias}/lease/{height}",
    )
    .with_projections(RouteProjections::SDK)
    .with_private_no_store();
    /// Read an original certified private-root registration or anchor record on its global parent.
    pub const PRIVATE_DATASPACE_RECORD_PROOF: RouteDescriptor = public_get(
        "private_dataspace.record_proof.read",
        "/v1/private-dataspaces/{dataspace_id}/records/{height}/proof",
    )
    .with_projections(RouteProjections::SDK);
    /// Export the immutable private root registration to its authenticated owner token.
    pub const PRIVATE_ROOT_REGISTRATION: RouteDescriptor = public_get(
        "private_root.registration.read",
        "/v1/private-root/registration",
    )
    .with_authentication(AuthenticationPolicy::PrivateRootOwnerToken)
    .with_admission(AdmissionPolicy::AuthenticatedProtocolPrincipal)
    .with_private_no_store()
    .with_projections(RouteProjections::SDK);
    /// Export one body-free certified private-root anchor to its authenticated owner token.
    pub const PRIVATE_ROOT_ANCHOR: RouteDescriptor = public_get(
        "private_root.anchor.read",
        "/v1/private-root/anchors/{height}",
    )
    .with_authentication(AuthenticationPolicy::PrivateRootOwnerToken)
    .with_admission(AdmissionPolicy::AuthenticatedProtocolPrincipal)
    .with_private_no_store()
    .with_projections(RouteProjections::SDK);
    /// Read a self-contained bridge finality proof.
    pub const BRIDGE_FINALITY: RouteDescriptor =
        public_get("bridge.finality_proof.read", "/v1/bridge/finality/{height}");
    /// Read at most 64 consecutive self-contained full proofs under one finite source owner.
    pub const BRIDGE_FINALITY_INTERVAL: RouteDescriptor = public_get(
        "bridge.finality_interval.read",
        "/v1/bridge/finality/interval/{from}/{to}",
    );
    /// Read a challenge-bound node-signed durable-tip finality attestation.
    pub const BRIDGE_FINALITY_ATTESTATION: RouteDescriptor = public_get(
        "bridge.finality_attestation.read",
        "/v1/bridge/finality/attestation/{height}",
    )
    .with_projections(RouteProjections::OPENAPI);
    /// Read the same challenge-bound attestation for whichever height is the durable tip.
    pub const BRIDGE_FINALITY_ATTESTATION_LATEST: RouteDescriptor = public_get(
        "bridge.finality_attestation.read_latest",
        "/v1/bridge/finality/attestation/latest",
    )
    .with_projections(RouteProjections::OPENAPI);
    /// Read a bridge finality commitment and justification bundle.
    pub const BRIDGE_FINALITY_BUNDLE: RouteDescriptor = public_get(
        "bridge.finality_bundle.read",
        "/v1/bridge/finality/bundle/{height}",
    );
    /// List registered consensus keys as an authenticated operator.
    pub const CONSENSUS_KEYS: RouteDescriptor =
        telemetry_operator_get("sumeragi.consensus_key.list", "/v1/sumeragi/consensus-keys");
    /// Read effective Sumeragi parameters as an authenticated operator.
    pub const PARAMETERS: RouteDescriptor =
        telemetry_operator_get("sumeragi.parameter.read", "/v1/sumeragi/params");
    /// Complete route family registered by `add_sumeragi_routes`.
    pub const ROUTES: &[RouteDescriptor] = &[
        EVIDENCE_COUNT,
        EVIDENCE_LIST,
        STATUS,
        DIAGNOSTICS,
        STATUS_SSE,
        LANES,
        BLS_KEYS,
        PRIVATE_DATASPACE_RECORD_PROOF,
        SNS_DATASPACE_LEASE,
        PRIVATE_ROOT_REGISTRATION,
        PRIVATE_ROOT_ANCHOR,
        BRIDGE_FINALITY,
        BRIDGE_FINALITY_INTERVAL,
        BRIDGE_FINALITY_ATTESTATION,
        BRIDGE_FINALITY_ATTESTATION_LATEST,
        BRIDGE_FINALITY_BUNDLE,
        CONSENSUS_KEYS,
        PARAMETERS,
    ];
}
/// Runtime, zero-knowledge, node-projection, and governance routes.
pub mod runtime_governance {
    use super::{
        AdmissionPolicy, ApiSurface, AuthenticationPolicy, FeatureGate, HttpMethod, Listener,
        PathPolicy, RouteDescriptor, RouteEffect, RouteProjections, RouteTransport,
    };
    const fn public_get(id: &'static str, path: &'static str) -> RouteDescriptor {
        RouteDescriptor::new(
            id,
            HttpMethod::Get,
            path,
            ApiSurface::Public,
            Listener::Torii,
            RouteEffect::ReadOnly,
            AdmissionPolicy::Public,
        )
        .with_projections(RouteProjections::OPENAPI_AND_SDK)
        .with_cors_options(true)
    }
    const fn public_post(id: &'static str, path: &'static str) -> RouteDescriptor {
        RouteDescriptor::new(
            id,
            HttpMethod::Post,
            path,
            ApiSurface::Public,
            Listener::Torii,
            RouteEffect::ReadOnly,
            AdmissionPolicy::Public,
        )
        .with_projections(RouteProjections::OPENAPI_AND_SDK)
        .with_cors_options(true)
    }
    const fn app_post(id: &'static str, path: &'static str) -> RouteDescriptor {
        public_post(id, path).with_feature_gate(FeatureGate::Feature("app_api"))
    }
    include!("route_catalog/runtime_governance_helpers.rs");
    const fn operator_get(id: &'static str, path: &'static str) -> RouteDescriptor {
        RouteDescriptor::new(
            id,
            HttpMethod::Get,
            path,
            ApiSurface::Operator,
            Listener::Torii,
            RouteEffect::ReadOnly,
            AdmissionPolicy::Operator,
        )
        .with_authentication(AuthenticationPolicy::OperatorSignature)
        .with_projections(RouteProjections::OPENAPI)
    }
    const fn operator_post(id: &'static str, path: &'static str) -> RouteDescriptor {
        RouteDescriptor::new(
            id,
            HttpMethod::Post,
            path,
            ApiSurface::Operator,
            Listener::Torii,
            RouteEffect::Mutation,
            AdmissionPolicy::Operator,
        )
        .with_authentication(AuthenticationPolicy::OperatorSignature)
        .with_projections(RouteProjections::OPENAPI)
    }
    const fn app_operator_get(id: &'static str, path: &'static str) -> RouteDescriptor {
        operator_get(id, path).with_feature_gate(FeatureGate::Feature("app_api"))
    }
    const fn app_operator_post(id: &'static str, path: &'static str) -> RouteDescriptor {
        operator_post(id, path).with_feature_gate(FeatureGate::Feature("app_api"))
    }
    /// Read registered zero-knowledge roots.
    pub const ZK_ROOTS: RouteDescriptor = account_compute_post("zk.roots.read", "/v1/zk/roots");
    /// Build a zero-knowledge Merkle path.
    pub const ZK_MERKLE_PATH: RouteDescriptor =
        account_compute_post("zk.merkle_path.build", "/v1/zk/merkle-path");
    /// Read a zero-knowledge vote tally.
    pub const ZK_VOTE_TALLY: RouteDescriptor =
        account_read_post("zk.vote.tally", "/v1/zk/vote/tally")
            .with_projections(RouteProjections::ALL);
    /// Verify a bounded batch of zero-knowledge proofs.
    pub const ZK_VERIFY_BATCH: RouteDescriptor =
        account_compute_post("zk.proof.verify_batch", "/v1/zk/verify-batch")
            .with_feature_gate(FeatureGate::Feature("zk-verify-batch"));
    /// List filtered zero-knowledge attachments.
    pub const ZK_ATTACHMENTS_GET: RouteDescriptor =
        app_signed_get("zk.attachment.list", "/v1/zk/attachments");
    /// Create a zero-knowledge attachment.
    pub const ZK_ATTACHMENTS_POST: RouteDescriptor =
        app_post("zk.attachment.create", "/v1/zk/attachments")
            .with_effect(RouteEffect::Mutation)
            .with_admission(AdmissionPolicy::AuthenticatedAccount)
            .with_authentication(AuthenticationPolicy::CanonicalAccountSignature);
    /// Read one zero-knowledge attachment.
    pub const ZK_ATTACHMENT_GET: RouteDescriptor =
        app_signed_get("zk.attachment.read", "/v1/zk/attachments/{id}");
    /// Delete one zero-knowledge attachment.
    pub const ZK_ATTACHMENT_DELETE: RouteDescriptor =
        app_signed_delete("zk.attachment.delete", "/v1/zk/attachments/{id}");
    /// Count filtered zero-knowledge attachments.
    pub const ZK_ATTACHMENTS_COUNT: RouteDescriptor =
        app_signed_get("zk.attachment.count", "/v1/zk/attachments/count");
    /// Read the active runtime ABI version.
    pub const RUNTIME_ABI_ACTIVE: RouteDescriptor =
        signed_get("runtime.abi.active", "/v1/runtime/abi/active");
    /// Read the active runtime ABI hash.
    pub const RUNTIME_ABI_HASH: RouteDescriptor =
        public_get("runtime.abi.hash", "/v1/runtime/abi/hash");
    /// Read bounded runtime metrics.
    pub const RUNTIME_METRICS: RouteDescriptor =
        account_compute_get("runtime.metrics", "/v1/runtime/metrics");
    /// Read node-wide compatibility metadata before account registration or submission.
    pub const NODE_CAPABILITIES: RouteDescriptor =
        public_get("node.capabilities", "/v1/node/capabilities");
    /// Read the authoritative committed privacy capability snapshot.
    pub const PRIVACY_CAPABILITIES: RouteDescriptor =
        signed_get("privacy.capabilities", "/v1/privacy/capabilities");
    /// Mint one canonical Bootle/Lantern blind-issuance authorization.
    pub const PRIVACY_BOOTLE_LANTERN_ISSUANCE_AUTHORIZE: RouteDescriptor = public_post(
        "privacy.bootle_lantern.issuance.authorize",
        "/v1/privacy/bootle-lantern/issuance/authorize",
    )
    .with_authentication(AuthenticationPolicy::ProtocolHandshake)
    .with_effect(RouteEffect::Mutation)
    .with_admission(AdmissionPolicy::AuthenticatedProtocolPrincipal);
    /// Issue one canonical Bootle/Lantern blind credential.
    pub const PRIVACY_BOOTLE_LANTERN_ISSUANCE_ISSUE: RouteDescriptor = public_post(
        "privacy.bootle_lantern.issuance.issue",
        "/v1/privacy/bootle-lantern/issuance/issue",
    )
    .with_authentication(AuthenticationPolicy::ProtocolHandshake)
    .with_effect(RouteEffect::Mutation)
    .with_admission(AdmissionPolicy::AuthenticatedProtocolPrincipal);
    /// Read the latest query-projection checkpoint.
    pub const NODE_PROJECTION_CHECKPOINT: RouteDescriptor = signed_get(
        "node.query_projection.checkpoint",
        "/v1/node/query/projection/checkpoint",
    );
    /// List canonical query-projection shards.
    pub const NODE_PROJECTION_SHARD_CATALOG: RouteDescriptor = app_operator_get(
        "operator.node.query_projection.shard_catalog",
        "/v1/node/query/projection/catalog/{resource}",
    );
    /// Export one canonical query-projection shard archive.
    pub const NODE_PROJECTION_SHARD_EXPORT: RouteDescriptor = app_operator_get(
        "operator.node.query_projection.shard_export",
        "/v1/node/query/projection/shards/{resource}/{partition_id}",
    );
    /// List staged runtime upgrades.
    pub const RUNTIME_UPGRADES: RouteDescriptor =
        operator_get("operator.runtime.upgrade.list", "/v1/runtime/upgrades");
    /// Propose a runtime upgrade.
    pub const RUNTIME_UPGRADE_PROPOSE: RouteDescriptor = operator_post(
        "operator.runtime.upgrade.propose",
        "/v1/runtime/upgrades/propose",
    );
    /// Activate a runtime upgrade.
    pub const RUNTIME_UPGRADE_ACTIVATE: RouteDescriptor = operator_post(
        "operator.runtime.upgrade.activate",
        "/v1/runtime/upgrades/activate/{id}",
    );
    /// Cancel a runtime upgrade.
    pub const RUNTIME_UPGRADE_CANCEL: RouteDescriptor = operator_post(
        "operator.runtime.upgrade.cancel",
        "/v1/runtime/upgrades/cancel/{id}",
    );
    /// Draft a ministry agenda proposal for local signing.
    pub const MINISTRY_AGENDA_DRAFT: RouteDescriptor = app_signed_post(
        "ministry.agenda_proposal.draft",
        "/v1/ministry/agenda/proposals/draft",
    );
    /// Read a submitted ministry agenda proposal.
    pub const MINISTRY_AGENDA_GET: RouteDescriptor = app_signed_get(
        "ministry.agenda_proposal.read",
        "/v1/ministry/agenda/proposals/{proposal_id}",
    );
    /// Draft a contract-deployment proposal.
    pub const GOV_PROPOSE_DEPLOY: RouteDescriptor = app_signed_post(
        "governance.proposal.deploy_contract",
        "/v1/gov/proposals/deploy-contract",
    );
    /// Draft an SCCP route-governance proposal.
    pub const GOV_PROPOSE_SCCP: RouteDescriptor = app_signed_post(
        "governance.proposal.sccp_route_governance",
        "/v1/gov/proposals/sccp-route-governance",
    );
    /// Read authenticated governance readiness and policy capabilities.
    pub const GOV_CAPABILITIES: RouteDescriptor =
        app_signed_get("governance.capabilities.read", "/v1/gov/capabilities");
    /// Draft the exact configured citizenship registration instruction.
    pub const GOV_CITIZEN_DRAFT: RouteDescriptor =
        app_signed_post("governance.citizen.draft", "/v1/gov/citizens/draft");
    /// Draft one canonical attempt-based Parliament proposal for local signing.
    pub const GOV_PARLIAMENT_ATTEMPT_DRAFT: RouteDescriptor = app_signed_post(
        "governance.parliament.attempt.draft",
        "/v1/gov/parliament/attempts/draft",
    );
    /// Read one complete canonical Parliament attempt projection.
    pub const GOV_PARLIAMENT_ATTEMPT_READ: RouteDescriptor = app_signed_get(
        "governance.parliament.attempt.read",
        "/v1/gov/parliament/attempts/{governance_attempt_id}",
    );
    /// Read the driver plan of one Parliament attempt.
    pub const GOV_PARLIAMENT_ATTEMPT_PLAN: RouteDescriptor = app_signed_get(
        "governance.parliament.attempt.plan",
        "/v1/gov/parliament/attempts/{governance_attempt_id}/plan",
    );
    /// Inspect one node-local replay-validated timed-OVN context (never wallet input).
    pub const GOV_PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_READ: RouteDescriptor = app_signed_get(
        "governance.parliament.timed_ovn_casting_context.read",
        "/v1/gov/parliament/ballots/{ballot_attempt_id}/casting-context",
    );
    /// Fetch one consensus-authenticated timed-OVN casting archive or checkpoint page.
    pub const GOV_PARLIAMENT_TIMED_OVN_CASTING_PROOF: RouteDescriptor = app_compute_post(
        "governance.parliament.timed_ovn_casting_proof.read",
        "/v1/gov/parliament/ballots/{ballot_attempt_id}/casting-proof",
    );
    /// Read one Core-authorized public TLE release context for a Parliament ballot.
    pub const GOV_PARLIAMENT_TLE_RELEASE_CONTEXT_READ: RouteDescriptor = app_signed_get(
        "governance.parliament.tle_release_context.read",
        "/v1/gov/parliament/ballots/{ballot_attempt_id}/release-context",
    );
    /// Request this node's Core-authorized proof-carrying TLE partial release.
    pub const GOV_PARLIAMENT_TLE_PARTIAL_RELEASE: RouteDescriptor = app_signed_post(
        "governance.parliament.tle_partial_release.create",
        "/v1/gov/parliament/ballots/{ballot_attempt_id}/partial-release",
    );
    /// Draft one closed Parliament lifecycle transition for local signing.
    pub const GOV_PARLIAMENT_TRANSITION_DRAFT: RouteDescriptor = app_signed_post(
        "governance.parliament.transition.draft",
        "/v1/gov/parliament/transitions/draft",
    );
    /// Finality-bound current validation-fee policy proof path.
    pub const VALIDATION_FEE_CURRENT_POLICY_PROOF_PATH: &str =
        "/v1/validation-fee/policy/current/proof";
    /// Authenticated native retail payment quote.
    pub const VALIDATION_FEE_RETAIL_QUOTE: RouteDescriptor =
        app_signed_post("validation_fee.retail.quote", "/v1/validation-fee/quote");
    /// Authenticated canonical wallet monthly fee status.
    pub const VALIDATION_FEE_RETAIL_STATUS: RouteDescriptor = app_signed_get(
        "validation_fee.retail.status",
        "/v1/validation-fee/accounts/{account_id}/status",
    );
    /// Authenticated immutable native fee receipts.
    pub const VALIDATION_FEE_RETAIL_RECEIPTS: RouteDescriptor = app_signed_get(
        "validation_fee.retail.receipts",
        "/v1/validation-fee/accounts/{account_id}/receipts",
    );
    /// Authenticated current cumulative wallet receipt head and finalized proof.
    pub const VALIDATION_FEE_RETAIL_STATEMENT_HEAD: RouteDescriptor = app_signed_get(
        "validation_fee.retail.statement_head",
        "/v1/validation-fee/accounts/{account_id}/statement/head",
    );
    /// Authenticated complete private wallet fee statement.
    pub const VALIDATION_FEE_RETAIL_STATEMENT: RouteDescriptor = app_signed_post(
        "validation_fee.retail.statement",
        "/v1/validation-fee/accounts/{account_id}/statement",
    );
    /// Typed validation-fee proposal list path.
    pub const VALIDATION_FEE_PROPOSALS_PATH: &str = "/v1/validation-fee/proposals";
    /// Typed validation-fee proposal detail path.
    pub const VALIDATION_FEE_PROPOSAL_DETAIL_PATH: &str =
        "/v1/validation-fee/proposals/{proposal_id}";
    /// Strict native validation-fee proposal draft path.
    pub const VALIDATION_FEE_PROPOSAL_DRAFT_PATH: &str = "/v1/validation-fee/proposals/draft";
    /// Fetch a finality-bound current validation-fee registry.
    pub const VALIDATION_FEE_CURRENT_POLICY_PROOF: RouteDescriptor = app_compute_post(
        "validation_fee.policy.current_proof",
        VALIDATION_FEE_CURRENT_POLICY_PROOF_PATH,
    );
    /// List typed validation-fee Parliament proposals.
    pub const VALIDATION_FEE_PROPOSALS: RouteDescriptor = app_signed_get(
        "validation_fee.proposal.list",
        VALIDATION_FEE_PROPOSALS_PATH,
    );
    /// Read one typed validation-fee Parliament proposal.
    pub const VALIDATION_FEE_PROPOSAL_DETAIL: RouteDescriptor = app_compute_get(
        "validation_fee.proposal.read",
        VALIDATION_FEE_PROPOSAL_DETAIL_PATH,
    );
    /// Draft one strict native validation-fee Parliament proposal.
    pub const VALIDATION_FEE_PROPOSAL_DRAFT: RouteDescriptor = app_signed_post(
        "validation_fee.proposal.draft",
        VALIDATION_FEE_PROPOSAL_DRAFT_PATH,
    );
    /// Read one governance proposal.
    pub const GOV_PROPOSAL_GET: RouteDescriptor =
        app_signed_get("governance.proposal.read", "/v1/gov/proposals/{id}");
    /// Read token locks for one referendum.
    pub const GOV_LOCKS_GET: RouteDescriptor =
        app_compute_get("governance.lock.list", "/v1/gov/locks/{rid}");
    /// Read one referendum.
    pub const GOV_REFERENDUM_GET: RouteDescriptor =
        app_signed_get("governance.referendum.read", "/v1/gov/referenda/{id}");
    /// Read a referendum tally snapshot.
    pub const GOV_TALLY_GET: RouteDescriptor =
        app_compute_get("governance.tally.read", "/v1/gov/tally/{id}");
    /// Draft a standalone version-one zero-knowledge referendum ballot instruction.
    pub const GOV_BALLOT_ZK_V1: RouteDescriptor =
        app_post("governance.ballot.zk_v1", "/v1/gov/ballots/zk-v1")
            .with_admission(AdmissionPolicy::AuthenticatedAccount)
            .with_authentication(AuthenticationPolicy::CanonicalAccountSignature);
    /// Draft a standalone version-one zero-knowledge referendum ballot proof instruction.
    pub const GOV_BALLOT_ZK_V1_PROOF: RouteDescriptor = app_post(
        "governance.ballot.zk_v1_proof",
        "/v1/gov/ballots/zk-v1/ballot-proof",
    )
    .with_admission(AdmissionPolicy::AuthenticatedAccount)
    .with_authentication(AuthenticationPolicy::CanonicalAccountSignature);
    /// Draft a standalone plain referendum ballot instruction.
    pub const GOV_BALLOT_PLAIN: RouteDescriptor =
        app_post("governance.ballot.plain", "/v1/gov/ballots/plain")
            .with_admission(AdmissionPolicy::AuthenticatedAccount)
            .with_authentication(AuthenticationPolicy::CanonicalAccountSignature);

    /// Replace the protected namespace set.
    pub const GOV_PROTECTED_POST: RouteDescriptor = app_operator_post(
        "operator.governance.protected_namespaces.update",
        "/v1/gov/protected-namespaces",
    )
    .with_projections(RouteProjections::OPENAPI.union(RouteProjections::MCP));
    /// Read the protected namespace set.
    pub const GOV_PROTECTED_GET: RouteDescriptor = app_signed_get(
        "governance.protected_namespaces.read",
        "/v1/gov/protected-namespaces",
    );
    /// Stream governance events over SSE.
    pub const GOV_STREAM: RouteDescriptor = RouteDescriptor::new(
        "governance.events.stream_sse",
        HttpMethod::Get,
        "/v1/gov/stream",
        ApiSurface::Protocol,
        Listener::Torii,
        RouteEffect::LongLivedStream,
        AdmissionPolicy::AuthenticatedAccount,
    )
    .with_feature_gate(FeatureGate::Feature("app_api"))
    .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
    .with_transport(RouteTransport::ServerSentEvents)
    .with_projections(RouteProjections::OPENAPI)
    .with_path_policy(PathPolicy::ProtocolException {
        reason: "governance SSE transport endpoint",
    });
    /// Read governance unlock statistics.
    pub const GOV_UNLOCK_STATS: RouteDescriptor =
        app_signed_get("governance.unlock.stats", "/v1/gov/unlocks/stats");
    /// Read the retained governance lifecycle for a contract, whether active or inactive.
    pub const GOV_CONTRACT_GET: RouteDescriptor = app_signed_get(
        "governance.contract.read",
        "/v1/gov/contracts/{contract_address}",
    );

    /// Read the exact citizenship registry count.
    pub const GOV_CITIZENS_COUNT: RouteDescriptor =
        app_signed_get("governance.citizen.count", "/v1/gov/citizens");
    /// Read citizenship status for one account.
    pub const GOV_CITIZEN_STATUS: RouteDescriptor =
        app_signed_get("governance.citizen.status", "/v1/gov/citizens/{account_id}");
    /// Complete route family registered by `add_runtime_governance_routes`.
    pub const ROUTES: &[RouteDescriptor] = &[
        ZK_ROOTS,
        ZK_MERKLE_PATH,
        ZK_VOTE_TALLY,
        ZK_VERIFY_BATCH,
        ZK_ATTACHMENTS_GET,
        ZK_ATTACHMENTS_POST,
        ZK_ATTACHMENT_GET,
        ZK_ATTACHMENT_DELETE,
        ZK_ATTACHMENTS_COUNT,
        RUNTIME_ABI_ACTIVE,
        RUNTIME_ABI_HASH,
        RUNTIME_METRICS,
        NODE_CAPABILITIES,
        PRIVACY_CAPABILITIES,
        PRIVACY_BOOTLE_LANTERN_ISSUANCE_AUTHORIZE,
        PRIVACY_BOOTLE_LANTERN_ISSUANCE_ISSUE,
        NODE_PROJECTION_CHECKPOINT,
        NODE_PROJECTION_SHARD_CATALOG,
        NODE_PROJECTION_SHARD_EXPORT,
        RUNTIME_UPGRADES,
        RUNTIME_UPGRADE_PROPOSE,
        RUNTIME_UPGRADE_ACTIVATE,
        RUNTIME_UPGRADE_CANCEL,
        MINISTRY_AGENDA_DRAFT,
        MINISTRY_AGENDA_GET,
        GOV_PROPOSE_DEPLOY,
        GOV_PROPOSE_SCCP,
        GOV_CAPABILITIES,
        GOV_CITIZEN_DRAFT,
        GOV_PARLIAMENT_ATTEMPT_DRAFT,
        GOV_PARLIAMENT_ATTEMPT_READ,
        GOV_PARLIAMENT_ATTEMPT_PLAN,
        GOV_PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_READ,
        GOV_PARLIAMENT_TIMED_OVN_CASTING_PROOF,
        GOV_PARLIAMENT_TLE_RELEASE_CONTEXT_READ,
        GOV_PARLIAMENT_TLE_PARTIAL_RELEASE,
        GOV_PARLIAMENT_TRANSITION_DRAFT,
        VALIDATION_FEE_CURRENT_POLICY_PROOF,
        VALIDATION_FEE_RETAIL_QUOTE,
        VALIDATION_FEE_RETAIL_STATUS,
        VALIDATION_FEE_RETAIL_RECEIPTS,
        VALIDATION_FEE_RETAIL_STATEMENT,
        VALIDATION_FEE_RETAIL_STATEMENT_HEAD,
        VALIDATION_FEE_PROPOSALS,
        VALIDATION_FEE_PROPOSAL_DETAIL,
        VALIDATION_FEE_PROPOSAL_DRAFT,
        GOV_PROPOSAL_GET,
        GOV_LOCKS_GET,
        GOV_REFERENDUM_GET,
        GOV_TALLY_GET,
        GOV_BALLOT_ZK_V1,
        GOV_BALLOT_ZK_V1_PROOF,
        GOV_BALLOT_PLAIN,
        GOV_PROTECTED_POST,
        GOV_PROTECTED_GET,
        GOV_STREAM,
        GOV_UNLOCK_STATS,
        GOV_CONTRACT_GET,
        GOV_CITIZENS_COUNT,
        GOV_CITIZEN_STATUS,
    ];
}
#[path = "route_catalog/sorafs_pop.rs"]
mod sorafs_pop;
/// `SoraFS` discovery, storage, transparency, reputation, and gateway routes.
pub mod sorafs {
    pub use super::sorafs_pop::{
        POP_APPROVAL, POP_ENROLLMENT, POP_ENROLLMENT_STATUS, POP_ISSUE, POP_REGISTRY_PROJECTION,
        POP_REGISTRY_RECONCILE, POP_REGISTRY_SUBMIT, POP_REVOCATION, POP_VERIFY,
        POP_WALLET_ACKNOWLEDGE, POP_WALLET_DELIVERY, POP_WALLET_IMPORT, POP_WALLET_PROVE,
        POP_WALLET_SYNCHRONIZE,
    };
    use super::{
        AdmissionPolicy, ApiSurface, AuthenticationPolicy, FeatureGate, HttpMethod, Listener,
        PathPolicy, RouteDescriptor, RouteEffect, RouteMatch, RouteProjections, RouteTransport,
    };
    const fn public_get(
        stable_route_id: &'static str,
        path: &'static str,
        projections: RouteProjections,
    ) -> RouteDescriptor {
        RouteDescriptor::new(
            stable_route_id,
            HttpMethod::Get,
            path,
            ApiSurface::Public,
            Listener::Torii,
            RouteEffect::ReadOnly,
            AdmissionPolicy::Public,
        )
        .with_feature_gate(FeatureGate::Feature("app_api"))
        .with_projections(projections)
        .with_cors_options(true)
    }
    const fn public_gateway_get(
        stable_route_id: &'static str,
        path: &'static str,
        surface: ApiSurface,
        projections: RouteProjections,
    ) -> RouteDescriptor {
        RouteDescriptor::new(
            stable_route_id,
            HttpMethod::Get,
            path,
            surface,
            Listener::Torii,
            RouteEffect::ReadOnly,
            AdmissionPolicy::Public,
        )
        .with_authentication(AuthenticationPolicy::Unauthenticated)
        .with_projections(projections)
        .with_cors_options(true)
    }
    const fn public_post(
        stable_route_id: &'static str,
        path: &'static str,
        projections: RouteProjections,
    ) -> RouteDescriptor {
        RouteDescriptor::new(
            stable_route_id,
            HttpMethod::Post,
            path,
            ApiSurface::Public,
            Listener::Torii,
            RouteEffect::ReadOnly,
            AdmissionPolicy::Public,
        )
        .with_feature_gate(FeatureGate::Feature("app_api"))
        .with_projections(projections)
        .with_cors_options(true)
    }
    const fn documented_get(stable_route_id: &'static str, path: &'static str) -> RouteDescriptor {
        public_get(stable_route_id, path, RouteProjections::OPENAPI_AND_SDK)
    }
    const fn documented_post(stable_route_id: &'static str, path: &'static str) -> RouteDescriptor {
        public_post(stable_route_id, path, RouteProjections::OPENAPI_AND_SDK)
    }
    const fn authenticated_documented_get(
        stable_route_id: &'static str,
        path: &'static str,
    ) -> RouteDescriptor {
        documented_get(stable_route_id, path)
            .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
            .with_admission(AdmissionPolicy::AuthenticatedAccount)
    }
    const fn authenticated_documented_post(
        stable_route_id: &'static str,
        path: &'static str,
    ) -> RouteDescriptor {
        documented_post(stable_route_id, path)
            .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
            .with_effect(RouteEffect::Mutation)
            .with_admission(AdmissionPolicy::AuthenticatedAccount)
    }
    include!("route_catalog/sorafs_route_helpers.rs");
    const fn stream_get(stable_route_id: &'static str, path: &'static str) -> RouteDescriptor {
        RouteDescriptor::new(
            stable_route_id,
            HttpMethod::Get,
            path,
            ApiSurface::Protocol,
            Listener::Torii,
            RouteEffect::LongLivedStream,
            AdmissionPolicy::AuthenticatedAccount,
        )
        .with_feature_gate(FeatureGate::Feature("app_api"))
        .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
        .with_transport(RouteTransport::ServerSentEvents)
        .with_projections(RouteProjections::OPENAPI)
    }
    /// Read configured `SoraFS` publication peers.
    pub const STORAGE_PEERS: RouteDescriptor =
        documented_get("sorafs.storage_peer.list", "/v1/sorafs/storage/peers");
    /// List admitted `SoraFS` provider advertisements.
    pub const PROVIDERS: RouteDescriptor =
        documented_get("sorafs.provider.list", "/v1/sorafs/providers");
    /// Read current certified provider authority and its exact signed advert at a selected height.
    pub const PROVIDER_DISCOVERY: RouteDescriptor = public_get(
        "sorafs.provider_discovery.read",
        "/v1/sorafs/providers/{provider_id}/discovery/{height}",
        RouteProjections::SDK,
    )
    .with_private_no_store();
    /// Read exact native custody presence or absence independently of provider admission.
    pub const STREAM_TOKEN_CUSTODY: RouteDescriptor = public_get(
        "sorafs.stream_token_custody.read",
        "/v1/sorafs/providers/{provider_id}/custody/{height}",
        RouteProjections::SDK,
    )
    .with_private_no_store();
    /// Submit a `SoraFS` provider advertisement.
    pub const PROVIDER_ADVERT: RouteDescriptor = documented_post(
        "sorafs.provider_advert.submit",
        "/v1/sorafs/providers/advert",
    )
    .with_authentication(AuthenticationPolicy::ProtocolHandshake)
    .with_effect(RouteEffect::Mutation)
    .with_admission(AdmissionPolicy::AuthenticatedProtocolPrincipal);
    /// Resolve admitted providers assigned to one approved content root.
    pub const ROUTING_PROVIDERS: RouteDescriptor = delegated_routing_get(
        "sorafs.delegated_routing.providers",
        "/routing/v1/providers/{cid}",
    );
    /// Resolve one admitted and actively assigned provider peer.
    pub const ROUTING_PEERS: RouteDescriptor = delegated_routing_get(
        "sorafs.delegated_routing.peers",
        "/routing/v1/peers/{peer_id}",
    );
    /// Read the local `SoraFS` capacity state.
    pub const CAPACITY_STATE: RouteDescriptor =
        documented_get("sorafs.capacity.read", "/v1/sorafs/capacity/state");
    /// Read supervised finalized-ledger billing projector status.
    pub const BILLING_STATUS: RouteDescriptor =
        authenticated_documented_get("sorafs.billing.status", "/v1/sorafs/billing/status");
    /// List terminally published billing statements owned by the authenticated account.
    pub const BILLING_STATEMENTS: RouteDescriptor = authenticated_documented_get(
        "sorafs.billing_statement.list",
        "/v1/sorafs/billing/statements",
    );
    /// Read one exact terminally published billing statement owned by the authenticated account.
    pub const BILLING_STATEMENT: RouteDescriptor = authenticated_documented_get(
        "sorafs.billing_statement.read",
        "/v1/sorafs/billing/statements/{statement_id}",
    );
    /// Acknowledge one owned terminally published billing statement.
    pub const BILLING_STATEMENT_ACKNOWLEDGEMENTS: RouteDescriptor = authenticated_documented_post(
        "sorafs.billing_statement_acknowledgement.submit",
        "/v1/sorafs/billing/statements/{statement_id}/acknowledgements",
    );
    /// Read payload-free billing delivery reconciliation status.
    pub const BILLING_RECONCILIATION: RouteDescriptor = authenticated_documented_get(
        "sorafs.billing.reconciliation",
        "/v1/sorafs/billing/reconciliation",
    );
    /// Read a bounded finalized active-epoch exposure page.
    pub const HEDGING_EXPOSURE: RouteDescriptor = authenticated_documented_get(
        "sorafs.hedging_exposure.list",
        "/v1/sorafs/hedging/exposure",
    );
    /// Read a bounded finalized active-epoch hedge-intent page.
    pub const HEDGING_INTENTS: RouteDescriptor =
        authenticated_documented_get("sorafs.hedging_intent.list", "/v1/sorafs/hedging/intents");
    /// Read the local Governance DAG dashboard.
    pub const GOVERNANCE_DAG_DASHBOARD: RouteDescriptor = operator_local_get(
        "sorafs.governance_dag.dashboard",
        "/v1/sorafs/governance/dag/dashboard",
    );
    /// Read the local Governance DAG head.
    pub const GOVERNANCE_DAG_HEAD: RouteDescriptor = operator_local_get(
        "sorafs.governance_dag.head",
        "/v1/sorafs/governance/dag/head",
    );
    /// Read one local Governance DAG block.
    pub const GOVERNANCE_DAG_BLOCK: RouteDescriptor = operator_local_get(
        "sorafs.governance_dag.block",
        "/v1/sorafs/governance/dag/blocks/{block_cid_hex}",
    );
    /// Read one local Governance DAG node.
    pub const GOVERNANCE_DAG_NODE: RouteDescriptor = operator_local_get(
        "sorafs.governance_dag.node",
        "/v1/sorafs/governance/dag/nodes/{node_cid_hex}",
    );
    /// Read the local Governance DAG publication index.
    pub const GOVERNANCE_DAG_PUBLISH_INDEX: RouteDescriptor = operator_local_get(
        "sorafs.governance_dag.publish_index",
        "/v1/sorafs/governance/dag/publish-index",
    );
    /// Read a publication-index entry by digest.
    pub const GOVERNANCE_DAG_PUBLISH_DIGEST: RouteDescriptor = operator_local_get(
        "sorafs.governance_dag.publish_digest",
        "/v1/sorafs/governance/dag/publish-index/digests/{encoded_blake3_hex}",
    );
    /// Read publication-index entries by payload kind.
    pub const GOVERNANCE_DAG_PUBLISH_KIND: RouteDescriptor = operator_local_get(
        "sorafs.governance_dag.publish_kind",
        "/v1/sorafs/governance/dag/publish-index/kinds/{payload_kind}",
    );
    /// List published transparency cycles.
    pub const TRANSPARENCY_CYCLES: RouteDescriptor = documented_get(
        "sorafs.transparency_cycle.list",
        "/v1/sorafs/transparency/cycles",
    );
    /// Read one published transparency cycle.
    pub const TRANSPARENCY_CYCLE: RouteDescriptor = documented_get(
        "sorafs.transparency_cycle.read",
        "/v1/sorafs/transparency/cycles/{cycle_id_hex}",
    );
    /// Read one transparency-cycle entry proof.
    pub const TRANSPARENCY_CYCLE_ENTRY: RouteDescriptor = documented_get(
        "sorafs.transparency_cycle_entry.read",
        "/v1/sorafs/transparency/cycles/{cycle_id_hex}/entries/{entry_id_hex}",
    );
    /// Read a transparency explorer snapshot.
    pub const TRANSPARENCY_EXPLORER: RouteDescriptor = documented_get(
        "sorafs.transparency_explorer.read",
        "/v1/sorafs/transparency/explorer",
    );
    /// Read the browser-native transparency explorer UI.
    pub const TRANSPARENCY_EXPLORER_UI: RouteDescriptor = public_get(
        "sorafs.transparency_explorer.ui",
        "/v1/sorafs/transparency/explorer/ui",
        RouteProjections::OPENAPI,
    );
    /// Submit a privacy-aggregate source event.
    pub const TRANSPARENCY_PRIVACY_SOURCE_EVENT: RouteDescriptor = authenticated_documented_post(
        "sorafs.transparency_privacy_aggregate.source_event",
        "/v1/sorafs/transparency/privacy-aggregates/source-events",
    );
    /// Publish the oldest due privacy-aggregate cycle.
    pub const TRANSPARENCY_PRIVACY_PUBLISH_DUE: RouteDescriptor = authenticated_documented_post(
        "sorafs.transparency_privacy_aggregate.publish_due",
        "/v1/sorafs/transparency/privacy-aggregates/publish-due",
    );
    /// List published proof-token issuances.
    pub const TRANSPARENCY_TOKENS: RouteDescriptor = documented_get(
        "sorafs.transparency_token.list",
        "/v1/sorafs/transparency/tokens",
    );
    /// Submit a proof-token issuance.
    pub const TRANSPARENCY_TOKEN_ISSUANCE: RouteDescriptor = authenticated_documented_post(
        "sorafs.transparency_token.issue",
        "/v1/sorafs/transparency/tokens/issuances",
    );
    /// Verify a `SoraFS` proof token.
    pub const TRANSPARENCY_TOKEN_VERIFY: RouteDescriptor = documented_post(
        "sorafs.transparency_token.verify",
        "/v1/sorafs/transparency/tokens/verify",
    );
    /// List local appeal-finance reports.
    pub const APPEAL_FINANCE_REPORTS_GET: RouteDescriptor = documented_get(
        "sorafs.appeal_finance_report.list",
        "/v1/sorafs/appeals/finance/reports",
    );
    /// Publish an appeal-finance report.
    pub const APPEAL_FINANCE_REPORTS_POST: RouteDescriptor = authenticated_documented_post(
        "sorafs.appeal_finance_report.publish",
        "/v1/sorafs/appeals/finance/reports",
    );
    /// List local appeal-finance weekly rollups.
    pub const APPEAL_FINANCE_WEEKLY_ROLLUPS_GET: RouteDescriptor = documented_get(
        "sorafs.appeal_finance_weekly_rollup.list",
        "/v1/sorafs/appeals/finance/weekly-rollups",
    );
    /// Publish an appeal-finance weekly rollup.
    pub const APPEAL_FINANCE_WEEKLY_ROLLUPS_POST: RouteDescriptor = authenticated_documented_post(
        "sorafs.appeal_finance_weekly_rollup.publish",
        "/v1/sorafs/appeals/finance/weekly-rollups",
    );
    /// List local appeal-finance settlement receipts.
    pub const APPEAL_FINANCE_SETTLEMENT_RECEIPTS: RouteDescriptor = documented_get(
        "sorafs.appeal_finance_settlement_receipt.list",
        "/v1/sorafs/appeals/finance/settlement-receipts",
    );
    /// Read the Governance DAG CAR-publication queue.
    pub const GOVERNANCE_DAG_CAR_QUEUE: RouteDescriptor = operator_local_get(
        "sorafs.governance_dag.car_queue",
        "/v1/sorafs/governance/dag/car-queue",
    );
    /// Read a queued CAR publication by digest.
    pub const GOVERNANCE_DAG_CAR_QUEUE_DIGEST: RouteDescriptor = operator_local_get(
        "sorafs.governance_dag.car_queue_digest",
        "/v1/sorafs/governance/dag/car-queue/digests/{encoded_blake3_hex}",
    );
    /// Read queued CAR publications by payload kind.
    pub const GOVERNANCE_DAG_CAR_QUEUE_KIND: RouteDescriptor = operator_local_get(
        "sorafs.governance_dag.car_queue_kind",
        "/v1/sorafs/governance/dag/car-queue/kinds/{payload_kind}",
    );
    /// Read a queued Governance DAG CAR archive.
    pub const GOVERNANCE_DAG_CAR_QUEUE_ARCHIVE: RouteDescriptor = operator_local_get(
        "sorafs.governance_dag.car_queue_archive",
        "/v1/sorafs/governance/dag/car-queue/archives/{car_archive_blake3_hex}",
    );
    /// Read the local Governance DAG runtime snapshot.
    pub const GOVERNANCE_DAG_RUNTIME: RouteDescriptor = operator_local_get(
        "sorafs.governance_dag.runtime",
        "/v1/sorafs/governance/dag/runtime",
    );
    /// Read the local Governance DAG runtime head.
    pub const GOVERNANCE_DAG_RUNTIME_HEAD: RouteDescriptor = operator_local_get(
        "sorafs.governance_dag.runtime_head",
        "/v1/sorafs/governance/dag/runtime/head",
    );
    /// Read one Governance DAG runtime block.
    pub const GOVERNANCE_DAG_RUNTIME_BLOCK: RouteDescriptor = operator_local_get(
        "sorafs.governance_dag.runtime_block",
        "/v1/sorafs/governance/dag/runtime/blocks/{block_cid_hex}",
    );
    /// Read one Governance DAG runtime node.
    pub const GOVERNANCE_DAG_RUNTIME_NODE: RouteDescriptor = operator_local_get(
        "sorafs.governance_dag.runtime_node",
        "/v1/sorafs/governance/dag/runtime/nodes/{node_cid_hex}",
    );
    /// Read a Governance DAG runtime entry by digest.
    pub const GOVERNANCE_DAG_RUNTIME_DIGEST: RouteDescriptor = operator_local_get(
        "sorafs.governance_dag.runtime_digest",
        "/v1/sorafs/governance/dag/runtime/digests/{encoded_blake3_hex}",
    );
    /// Read Governance DAG runtime entries by payload kind.
    pub const GOVERNANCE_DAG_RUNTIME_KIND: RouteDescriptor = operator_local_get(
        "sorafs.governance_dag.runtime_kind",
        "/v1/sorafs/governance/dag/runtime/kinds/{payload_kind}",
    );
    /// Read the latest reputation snapshot.
    pub const REPUTATION_LATEST_GET: RouteDescriptor = authenticated_documented_get(
        "sorafs.reputation_snapshot.latest",
        "/v1/sorafs/reputation/latest",
    );
    /// Read one historical reputation snapshot.
    pub const REPUTATION_SNAPSHOT: RouteDescriptor = authenticated_documented_get(
        "sorafs.reputation_snapshot.read",
        "/v1/sorafs/reputation/snapshots/{snapshot_id_hex}",
    );
    /// Read one provider's reputation record and proof.
    pub const REPUTATION_PROVIDER: RouteDescriptor = authenticated_documented_get(
        "sorafs.reputation_provider.read",
        "/v1/sorafs/reputation/providers/{provider_id}",
    );
    /// Read the active reputation weights.
    pub const REPUTATION_WEIGHTS: RouteDescriptor = authenticated_documented_get(
        "sorafs.reputation_weight.read",
        "/v1/sorafs/reputation/weights",
    );
    /// Read a bounded reputation-event snapshot.
    pub const REPUTATION_EVENTS: RouteDescriptor = authenticated_documented_get(
        "sorafs.reputation_event.list",
        "/v1/sorafs/reputation/events",
    );
    /// Stream reputation events over SSE.
    pub const REPUTATION_EVENTS_STREAM: RouteDescriptor = stream_get(
        "protocol.sorafs.reputation_event_stream",
        "/v1/sorafs/reputation/events/stream",
    )
    .with_authentication(AuthenticationPolicy::CanonicalAccountSignature);
    /// Stream reputation events over WebSocket.
    pub const REPUTATION_EVENTS_WEBSOCKET: RouteDescriptor = stream_get(
        "protocol.sorafs.reputation_event_websocket",
        "/v1/sorafs/reputation/events/ws",
    )
    .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
    .with_transport(RouteTransport::WebSocket);
    /// Read the `SoraFS` pin registry.
    pub const PIN_REGISTRY: RouteDescriptor = documented_get("sorafs.pin.list", "/v1/sorafs/pin");
    /// Read one `SoraFS` pin manifest.
    pub const PIN_MANIFEST: RouteDescriptor =
        documented_get("sorafs.pin.read", "/v1/sorafs/pin/{digest_hex}");
    /// Register a paid `SoraFS` pin manifest.
    pub const PIN_REGISTER: RouteDescriptor =
        documented_post("sorafs.pin.register", "/v1/sorafs/pin/register")
            .with_authentication(AuthenticationPolicy::CanonicalSignedBody)
            .with_effect(RouteEffect::Mutation)
            .with_admission(AdmissionPolicy::AuthenticatedAccount);
    /// Read one chunk under an exact finalized native repair lease.
    pub const REPAIR_SOURCE: RouteDescriptor =
        documented_post("sorafs.repair.source", "/v1/sorafs/repair/source")
            .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
            .with_effect(RouteEffect::ExpensiveCompute)
            .with_admission(AdmissionPolicy::AuthenticatedAccount);
    /// Read bounded source metadata or one chunk under a current native replication assignment.
    pub const PROVIDER_SOURCE: RouteDescriptor =
        documented_post("sorafs.provider.source", "/v1/sorafs/provider/source")
            .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
            .with_effect(RouteEffect::ExpensiveCompute)
            .with_admission(AdmissionPolicy::AuthenticatedAccount);
    /// Read one original signed provider attestation through current native archive-manager authorization.
    pub const PROVIDER_ATTESTATION: RouteDescriptor = documented_post(
        "sorafs.provider.attestation",
        "/v1/sorafs/provider/attestation",
    )
    .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
    .with_effect(RouteEffect::ExpensiveCompute)
    .with_admission(AdmissionPolicy::AuthenticatedAccount);
    /// Stage publisher-authenticated chunks for an exact finalized provider assignment.
    pub const PUBLISH_SOURCE: RouteDescriptor =
        documented_post("sorafs.publish_source.stage", "/v1/sorafs/publish/source")
            .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
            .with_effect(RouteEffect::Mutation)
            .with_admission(AdmissionPolicy::AuthenticatedAccount);
    /// Prepare exact current publication assertion inputs for their authenticated publisher.
    pub const PUBLISH_PREPARE: RouteDescriptor =
        documented_post("sorafs.publication.prepare", "/v1/sorafs/publish/prepare")
            .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
            .with_effect(RouteEffect::ExpensiveCompute)
            .with_admission(AdmissionPolicy::AuthenticatedAccount);
    /// Return native publication execution evidence to an authorized full-ledger reader.
    pub const PUBLISH_PROOF: RouteDescriptor =
        documented_post("sorafs.publication.proof", "/v1/sorafs/publish/proof")
            .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
            .with_effect(RouteEffect::ExpensiveCompute)
            .with_admission(AdmissionPolicy::AuthenticatedAccount);
    /// List `SoraFS` aliases after exact canonical-account authentication.
    pub const ALIASES: RouteDescriptor =
        authenticated_documented_get("sorafs.alias.list", "/v1/sorafs/aliases")
            .with_effect(RouteEffect::ExpensiveCompute);
    /// List `SoraFS` replication orders after exact canonical-account authentication.
    pub const REPLICATION: RouteDescriptor =
        authenticated_documented_get("sorafs.replication_order.list", "/v1/sorafs/replication")
            .with_effect(RouteEffect::ExpensiveCompute);
    /// Read operator-only local `SoraFS` storage state.
    pub const STORAGE_STATE: RouteDescriptor =
        operator_local_get("sorafs.storage_state.read", "/v1/sorafs/storage/state");
    /// Resolve a content identifier to stored manifest metadata.
    pub const CID_LOOKUP: RouteDescriptor = public_gateway_get(
        "sorafs.content_identifier.read",
        "/v1/sorafs/cid/{cid}",
        ApiSurface::Public,
        RouteProjections::SDK,
    );
    /// Read one stored manifest.
    pub const STORAGE_MANIFEST: RouteDescriptor = documented_get(
        "sorafs.storage_manifest.read",
        "/v1/sorafs/storage/manifest/{manifest_id}",
    );
    /// Read one stored manifest's chunk plan.
    pub const STORAGE_PLAN: RouteDescriptor = documented_get(
        "sorafs.storage_plan.read",
        "/v1/sorafs/storage/plan/{manifest_id}",
    );
    /// Request a storage access token.
    pub const STORAGE_TOKEN: RouteDescriptor =
        documented_post("sorafs.storage_token.issue", "/v1/sorafs/storage/token")
            .with_authentication(AuthenticationPolicy::OperatorSignature)
            .with_effect(RouteEffect::Mutation)
            .with_admission(AdmissionPolicy::Operator);
    /// Request an immutable-object token under the provider's explicit admitted account-read policy.
    pub const STORAGE_ACCOUNT_TOKEN: RouteDescriptor = documented_post(
        "sorafs.storage_account_token.issue",
        "/v1/sorafs/storage/token/account",
    )
    .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
    .with_effect(RouteEffect::Mutation)
    .with_admission(AdmissionPolicy::AuthenticatedAccount)
    .with_private_no_store();
    /// Read CAR bytes for a stored manifest.
    pub const STORAGE_CAR: RouteDescriptor = documented_get(
        "sorafs.storage_car.read",
        "/v1/sorafs/storage/car/{manifest_id}",
    )
    .with_authentication(AuthenticationPolicy::ProtocolHandshake)
    .with_admission(AdmissionPolicy::AuthenticatedProtocolPrincipal);
    /// Read one stored chunk.
    pub const STORAGE_CHUNK: RouteDescriptor = documented_get(
        "sorafs.storage_chunk.read",
        "/v1/sorafs/storage/chunk/{manifest_id}/{chunk_digest}",
    )
    .with_authentication(AuthenticationPolicy::ProtocolHandshake)
    .with_admission(AdmissionPolicy::AuthenticatedProtocolPrincipal);
    /// Build a bounded proof-stream payload.
    pub const PROOF_STREAM: RouteDescriptor =
        documented_post("sorafs.proof_stream.build", "/v1/sorafs/proof/stream")
            .with_authentication(AuthenticationPolicy::OperatorSignature)
            .with_effect(RouteEffect::ExpensiveCompute)
            .with_admission(AdmissionPolicy::Operator);
    /// Enqueue one council-admitted PDP challenge.
    pub const PDP_CHALLENGE: RouteDescriptor =
        documented_post("sorafs.pdp.challenge", "/v1/sorafs/pdp/challenge")
            .with_authentication(AuthenticationPolicy::OperatorSignature)
            .with_effect(RouteEffect::Mutation)
            .with_admission(AdmissionPolicy::Operator);
    /// Fetch the next pending PDP challenge for one provider.
    pub const PDP_NEXT: RouteDescriptor = documented_post("sorafs.pdp.next", "/v1/sorafs/pdp/next")
        .with_authentication(AuthenticationPolicy::OperatorSignature)
        .with_admission(AdmissionPolicy::Operator);
    /// Submit one challenge-bound PDP proof.
    pub const PDP_PROOF: RouteDescriptor =
        documented_post("sorafs.pdp.proof", "/v1/sorafs/pdp/proof")
            .with_authentication(AuthenticationPolicy::OperatorSignature)
            .with_effect(RouteEffect::Mutation)
            .with_admission(AdmissionPolicy::Operator);
    /// Read one retained PDP challenge status.
    pub const PDP_STATUS: RouteDescriptor =
        documented_post("sorafs.pdp.status", "/v1/sorafs/pdp/status")
            .with_authentication(AuthenticationPolicy::OperatorSignature)
            .with_admission(AdmissionPolicy::Operator);
    /// Export one bounded page of retained PDP statuses.
    pub const PDP_EXPORT: RouteDescriptor =
        documented_post("sorafs.pdp.export", "/v1/sorafs/pdp/export")
            .with_authentication(AuthenticationPolicy::OperatorSignature)
            .with_admission(AdmissionPolicy::Operator);
    /// Read the manifest selected by the request's `SoraFS` site binding.
    pub const SITE_MANIFEST: RouteDescriptor = public_gateway_get(
        "protocol.sorafs.site_manifest",
        "/.well-known/sorafs/manifest",
        ApiSurface::Protocol,
        RouteProjections::NONE,
    )
    .with_path_policy(PathPolicy::ProtocolException {
        reason: "well-known SoraFS site-manifest discovery endpoint",
    });
    /// Read the root document for one content-addressed `SoraFS` site.
    pub const CID_ROOT: RouteDescriptor = public_gateway_get(
        "protocol.sorafs.cid_root",
        "/sorafs/cid/{cid}",
        ApiSurface::Protocol,
        RouteProjections::NONE,
    )
    .with_path_policy(PathPolicy::ProtocolException {
        reason: "content-addressed SoraFS gateway root",
    });
    /// Read a path under one content-addressed `SoraFS` site.
    pub const CID_PATH: RouteDescriptor = public_gateway_get(
        "protocol.sorafs.cid_path",
        "/sorafs/cid/{cid}/{*path}",
        ApiSurface::Protocol,
        RouteProjections::NONE,
    )
    .with_route_match(RouteMatch::Wildcard)
    .with_path_policy(PathPolicy::ProtocolException {
        reason: "content-addressed SoraFS gateway wildcard",
    });
    /// Complete route family registered by the public-gateway and optional
    /// application/admin `SoraFS` route assemblers.
    pub const ROUTES: &[RouteDescriptor] = &[
        STORAGE_PEERS,
        PROVIDERS,
        PROVIDER_ADVERT,
        PROVIDER_DISCOVERY,
        STREAM_TOKEN_CUSTODY,
        ROUTING_PROVIDERS,
        ROUTING_PEERS,
        CAPACITY_STATE,
        BILLING_STATUS,
        BILLING_STATEMENTS,
        BILLING_STATEMENT,
        BILLING_STATEMENT_ACKNOWLEDGEMENTS,
        BILLING_RECONCILIATION,
        HEDGING_EXPOSURE,
        HEDGING_INTENTS,
        GOVERNANCE_DAG_DASHBOARD,
        GOVERNANCE_DAG_HEAD,
        GOVERNANCE_DAG_BLOCK,
        GOVERNANCE_DAG_NODE,
        GOVERNANCE_DAG_PUBLISH_INDEX,
        GOVERNANCE_DAG_PUBLISH_DIGEST,
        GOVERNANCE_DAG_PUBLISH_KIND,
        TRANSPARENCY_CYCLES,
        TRANSPARENCY_CYCLE,
        TRANSPARENCY_CYCLE_ENTRY,
        TRANSPARENCY_EXPLORER,
        TRANSPARENCY_EXPLORER_UI,
        TRANSPARENCY_PRIVACY_SOURCE_EVENT,
        TRANSPARENCY_PRIVACY_PUBLISH_DUE,
        TRANSPARENCY_TOKENS,
        TRANSPARENCY_TOKEN_ISSUANCE,
        TRANSPARENCY_TOKEN_VERIFY,
        APPEAL_FINANCE_REPORTS_GET,
        APPEAL_FINANCE_REPORTS_POST,
        APPEAL_FINANCE_WEEKLY_ROLLUPS_GET,
        APPEAL_FINANCE_WEEKLY_ROLLUPS_POST,
        APPEAL_FINANCE_SETTLEMENT_RECEIPTS,
        GOVERNANCE_DAG_CAR_QUEUE,
        GOVERNANCE_DAG_CAR_QUEUE_DIGEST,
        GOVERNANCE_DAG_CAR_QUEUE_KIND,
        GOVERNANCE_DAG_CAR_QUEUE_ARCHIVE,
        GOVERNANCE_DAG_RUNTIME,
        GOVERNANCE_DAG_RUNTIME_HEAD,
        GOVERNANCE_DAG_RUNTIME_BLOCK,
        GOVERNANCE_DAG_RUNTIME_NODE,
        GOVERNANCE_DAG_RUNTIME_DIGEST,
        GOVERNANCE_DAG_RUNTIME_KIND,
        REPUTATION_LATEST_GET,
        REPUTATION_SNAPSHOT,
        REPUTATION_PROVIDER,
        REPUTATION_WEIGHTS,
        REPUTATION_EVENTS,
        REPUTATION_EVENTS_STREAM,
        REPUTATION_EVENTS_WEBSOCKET,
        PIN_REGISTRY,
        PIN_MANIFEST,
        PIN_REGISTER,
        ALIASES,
        REPLICATION,
        STORAGE_STATE,
        CID_LOOKUP,
        STORAGE_MANIFEST,
        STORAGE_PLAN,
        REPAIR_SOURCE,
        PROVIDER_SOURCE,
        PROVIDER_ATTESTATION,
        PUBLISH_SOURCE,
        PUBLISH_PREPARE,
        PUBLISH_PROOF,
        STORAGE_TOKEN,
        STORAGE_ACCOUNT_TOKEN,
        STORAGE_CAR,
        STORAGE_CHUNK,
        PROOF_STREAM,
        PDP_CHALLENGE,
        PDP_NEXT,
        PDP_PROOF,
        PDP_STATUS,
        PDP_EXPORT,
        POP_ENROLLMENT,
        POP_ENROLLMENT_STATUS,
        POP_APPROVAL,
        POP_ISSUE,
        POP_REVOCATION,
        POP_REGISTRY_SUBMIT,
        POP_REGISTRY_RECONCILE,
        POP_REGISTRY_PROJECTION,
        POP_WALLET_DELIVERY,
        POP_WALLET_IMPORT,
        POP_WALLET_ACKNOWLEDGE,
        POP_WALLET_SYNCHRONIZE,
        POP_WALLET_PROVE,
        POP_VERIFY,
        SITE_MANIFEST,
        CID_ROOT,
        CID_PATH,
    ];
}
/// Application-facing resource, explorer, webhook, and protocol routes.
pub mod application_api {
    use super::{
        AdmissionPolicy, ApiSurface, AuthenticationPolicy, FeatureGate, HttpMethod, Listener,
        PathPolicy, RouteDescriptor, RouteEffect, RouteMatch, RouteProjections, RouteTransport,
    };
    const fn app_get(id: &'static str, path: &'static str) -> RouteDescriptor {
        RouteDescriptor::new(
            id,
            HttpMethod::Get,
            path,
            ApiSurface::Public,
            Listener::Torii,
            RouteEffect::ReadOnly,
            AdmissionPolicy::Public,
        )
        .with_feature_gate(FeatureGate::Feature("app_api"))
        .with_projections(RouteProjections::OPENAPI_AND_SDK)
        .with_cors_options(true)
    }
    const fn internal_get(id: &'static str, path: &'static str) -> RouteDescriptor {
        RouteDescriptor::new(
            id,
            HttpMethod::Get,
            path,
            ApiSurface::Public,
            Listener::Torii,
            RouteEffect::ReadOnly,
            AdmissionPolicy::Public,
        )
        .with_feature_gate(FeatureGate::Feature("app_api"))
        .with_projections(RouteProjections::NONE)
    }
    const fn app_post(id: &'static str, path: &'static str) -> RouteDescriptor {
        RouteDescriptor::new(
            id,
            HttpMethod::Post,
            path,
            ApiSurface::Public,
            Listener::Torii,
            RouteEffect::ReadOnly,
            AdmissionPolicy::Public,
        )
        .with_feature_gate(FeatureGate::Feature("app_api"))
        .with_projections(RouteProjections::OPENAPI_AND_SDK)
        .with_cors_options(true)
    }
    const fn app_sdk_get(id: &'static str, path: &'static str) -> RouteDescriptor {
        app_get(id, path).with_projections(RouteProjections::SDK)
    }
    const fn dataspace_get(id: &'static str, path: &'static str) -> RouteDescriptor {
        app_get(id, path)
            .with_admission(AdmissionPolicy::DataspaceVisible)
            .with_authentication(AuthenticationPolicy::OptionalCanonicalAccountSignature)
    }
    const fn dataspace_post(id: &'static str, path: &'static str) -> RouteDescriptor {
        app_post(id, path)
            .with_admission(AdmissionPolicy::DataspaceVisible)
            .with_authentication(AuthenticationPolicy::OptionalCanonicalAccountSignature)
    }
    const fn dataspace_sdk_get(id: &'static str, path: &'static str) -> RouteDescriptor {
        dataspace_get(id, path).with_projections(RouteProjections::SDK)
    }
    const fn app_sdk_post(id: &'static str, path: &'static str) -> RouteDescriptor {
        app_post(id, path).with_projections(RouteProjections::SDK)
    }
    include!("route_catalog/authenticated_post_helpers.rs");
    const fn onboarding_get(id: &'static str, path: &'static str) -> RouteDescriptor {
        app_get(id, path)
            .with_authentication(AuthenticationPolicy::OnboardingToken)
            .with_admission(AdmissionPolicy::Operator)
    }
    const fn onboarding_compute_post(id: &'static str, path: &'static str) -> RouteDescriptor {
        app_post(id, path)
            .with_authentication(AuthenticationPolicy::OnboardingToken)
            .with_effect(RouteEffect::ExpensiveCompute)
            .with_admission(AdmissionPolicy::Operator)
    }
    const fn faucet_protocol_compute_post(id: &'static str, path: &'static str) -> RouteDescriptor {
        app_post(id, path)
            .with_authentication(AuthenticationPolicy::ProtocolHandshake)
            .with_effect(RouteEffect::ExpensiveCompute)
            .with_admission(AdmissionPolicy::AuthenticatedProtocolPrincipal)
    }
    const fn faucet_protocol_mutation_post(
        id: &'static str,
        path: &'static str,
    ) -> RouteDescriptor {
        app_post(id, path)
            .with_authentication(AuthenticationPolicy::ProtocolHandshake)
            .with_effect(RouteEffect::Mutation)
            .with_admission(AdmissionPolicy::AuthenticatedProtocolPrincipal)
    }
    const fn app_delete(id: &'static str, path: &'static str) -> RouteDescriptor {
        RouteDescriptor::new(
            id,
            HttpMethod::Delete,
            path,
            ApiSurface::Public,
            Listener::Torii,
            RouteEffect::ReadOnly,
            AdmissionPolicy::Public,
        )
        .with_feature_gate(FeatureGate::Feature("app_api"))
        .with_projections(RouteProjections::OPENAPI_AND_SDK)
        .with_cors_options(true)
    }
    const fn app_wildcard_get(id: &'static str, path: &'static str) -> RouteDescriptor {
        app_sdk_get(id, path).with_route_match(RouteMatch::Wildcard)
    }
    const fn app_wildcard_post(id: &'static str, path: &'static str) -> RouteDescriptor {
        account_compute_sdk_post(id, path).with_route_match(RouteMatch::Wildcard)
    }
    const fn push_post(id: &'static str, path: &'static str) -> RouteDescriptor {
        app_post(id, path)
            .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
            .with_effect(RouteEffect::Mutation)
            .with_admission(AdmissionPolicy::AuthenticatedAccount)
            .with_feature_gate(FeatureGate::All(&["app_api", "push"]))
    }
    const fn push_delete(id: &'static str, path: &'static str) -> RouteDescriptor {
        app_delete(id, path)
            .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
            .with_effect(RouteEffect::Mutation)
            .with_admission(AdmissionPolicy::AuthenticatedAccount)
            .with_feature_gate(FeatureGate::All(&["app_api", "push"]))
    }
    const fn app_protocol_get(id: &'static str, path: &'static str) -> RouteDescriptor {
        RouteDescriptor::new(
            id,
            HttpMethod::Get,
            path,
            ApiSurface::Protocol,
            Listener::Torii,
            RouteEffect::LongLivedStream,
            AdmissionPolicy::AuthenticatedAccount,
        )
        .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
        .with_transport(RouteTransport::ServerSentEvents)
        .with_feature_gate(FeatureGate::Feature("app_api"))
        .with_projections(RouteProjections::OPENAPI)
        .with_path_policy(PathPolicy::ProtocolException {
            reason: "streaming transport endpoint",
        })
    }
    const fn dataspace_protocol_get(id: &'static str, path: &'static str) -> RouteDescriptor {
        app_protocol_get(id, path)
            .with_admission(AdmissionPolicy::DataspaceVisible)
            .with_authentication(AuthenticationPolicy::OptionalCanonicalAccountSignature)
    }
    const fn dataspace_telemetry_protocol_get(
        id: &'static str,
        path: &'static str,
    ) -> RouteDescriptor {
        dataspace_protocol_get(id, path)
            .with_feature_gate(FeatureGate::All(&["app_api", "telemetry"]))
    }
    const fn app_unprojected_protocol_get(id: &'static str, path: &'static str) -> RouteDescriptor {
        app_protocol_get(id, path).with_projections(RouteProjections::NONE)
    }
    const fn telemetry_diagnostic_get(id: &'static str, path: &'static str) -> RouteDescriptor {
        RouteDescriptor::new(
            id,
            HttpMethod::Get,
            path,
            ApiSurface::Diagnostic,
            Listener::Torii,
            RouteEffect::ReadOnly,
            AdmissionPolicy::Public,
        )
        .with_feature_gate(FeatureGate::All(&["app_api", "telemetry"]))
    }
    const fn telemetry_documented_get(id: &'static str, path: &'static str) -> RouteDescriptor {
        telemetry_diagnostic_get(id, path).with_projections(RouteProjections::OPENAPI)
    }
    const fn authenticated_telemetry_documented_get(
        id: &'static str,
        path: &'static str,
    ) -> RouteDescriptor {
        telemetry_documented_get(id, path)
            .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
            .with_admission(AdmissionPolicy::AuthenticatedAccount)
    }
    macro_rules! declare_routes {
        ($(
            $(#[doc = $doc:literal])*
            $name:ident => $factory:ident($id:literal, $path:literal);
        )+) => {
            $(
                #[doc = concat!("Descriptor for `", $path, "`.")]
                $(#[doc = $doc])*
                pub const $name: RouteDescriptor = $factory($id, $path);
            )+
            /// Complete application API route family.
            pub const ROUTES: &[RouteDescriptor] = &[$($name),+];
        };
    }
    declare_routes! {
        APP_API_BINDINGS_GET => app_sdk_get("application.app_api_bindings_get", "/v1/app-api/bindings");
        APP_API_CID_BY_CID_GET => app_sdk_get("application.app_api_cid_by_cid_get", "/v1/app-api/cid/{cid}");
        APP_API_CID_BY_CID_BY_PATH_GET => app_wildcard_get("application.app_api_cid_by_cid_by_path_get", "/v1/app-api/cid/{cid}/{*path}");
        APP_API_CID_BY_CID_BY_PATH_POST => app_wildcard_post("application.app_api_cid_by_cid_by_path_post", "/v1/app-api/cid/{cid}/{*path}");
        APP_API_ACTIVE_BY_PATH_GET => app_wildcard_get("application.app_api_active_by_path_get", "/v1/app-api/active/{*path}");
        APP_API_ACTIVE_BY_PATH_POST => app_wildcard_post("application.app_api_active_by_path_post", "/v1/app-api/active/{*path}");
        API_CID_BY_CID_GET => app_sdk_get("application.api_cid_by_cid_get", "/v1/api/cid/{cid}");
        API_CID_BY_CID_BY_PATH_GET => app_wildcard_get("application.api_cid_by_cid_by_path_get", "/v1/api/cid/{cid}/{*path}");
        API_CID_BY_CID_BY_PATH_POST => app_wildcard_post("application.api_cid_by_cid_by_path_post", "/v1/api/cid/{cid}/{*path}");
        ACCOUNTS_BY_ACCOUNT_ID_GET => dataspace_get("application.accounts_by_account_id_get", "/v1/accounts/{account_id}");
        INTERNAL_ACCOUNTS_BY_ACCOUNT_ID_GET => internal_get("application.internal_accounts_by_account_id_get", "/v1/internal/accounts/{account_id}");
        INTERNAL_ACCOUNTS_BY_ACCOUNT_ID_TRANSACTIONS_BY_ENTRYPOINT_HASH_GET => internal_get("application.internal_accounts_by_account_id_transactions_by_entrypoint_hash_get", "/v1/internal/accounts/{account_id}/transactions/{entrypoint_hash}");
        INTERNAL_ACCOUNTS_BY_ACCOUNT_ID_ASSETS_BY_ASSET_DEFINITION_ID_GET => internal_get("application.internal_accounts_by_account_id_assets_by_asset_definition_id_get", "/v1/internal/accounts/{account_id}/assets/{asset_definition_id}");
        ACCOUNTS_BY_ACCOUNT_ID_HISTORY_QUERY_POST => dataspace_post("application.accounts_by_account_id_history_query_post", "/v1/accounts/{account_id}/history/query");
        ACCOUNTS_BY_ACCOUNT_ID_TRANSACTIONS_QUERY_POST => dataspace_post("application.accounts_by_account_id_transactions_query_post", "/v1/accounts/{account_id}/transactions/query");
        ///
        /// Call-derived: one row per committed top-level `ContractCall`, projected from the
        /// signed invocation and its consensus-bound metadata; contracts emit no rows here.
        CONTRACTS_ACTIVITY_QUERY_POST => dataspace_post("application.contracts_activity_query_post", "/v1/contracts/activity/query");
        ///
        /// Call-derived: one row per committed top-level `ContractCall`, projected from the
        /// signed invocation and its consensus-bound metadata; contracts emit no rows here.
        CONTRACTS_EVENTS_QUERY_POST => dataspace_post("application.contracts_events_query_post", "/v1/contracts/events/query");
        ///
        /// Call-derived: one row per committed top-level `ContractCall`, projected from the
        /// signed invocation and its consensus-bound metadata; contracts emit no rows here.
        CONTRACTS_ACTIVITY_GET => dataspace_get("application.contracts_activity_get", "/v1/contracts/activity");
        ///
        /// Native events in committed execution outputs, retaining the emitting contract,
        /// signed declaration and execution coordinates.
        CONTRACTS_EVENTS_GET => dataspace_get("application.contracts_events_get", "/v1/contracts/events");
        CONTRACTS_ROLLUPS_SWAPS_FILLS_GET => dataspace_get("application.contracts_rollups_swaps_fills_get", "/v1/contracts/rollups/swaps/fills");
        CONTRACTS_ROLLUPS_SWAPS_CANDLES_GET => dataspace_get("application.contracts_rollups_swaps_candles_get", "/v1/contracts/rollups/swaps/candles");
        CONTRACTS_ROLLUPS_URANAI_MARKETS_HISTORY_GET => dataspace_get("application.contracts_rollups_uranai_markets_history_get", "/v1/contracts/rollups/uranai/markets/history");
        CONTRACTS_ROLLUPS_TRADER_ACTIVITY_GET => dataspace_get("application.contracts_rollups_trader_activity_get", "/v1/contracts/rollups/trader/activity");
        CONTRACTS_ROLLUPS_TRADER_ACCOUNT_GET => dataspace_get("application.contracts_rollups_trader_account_get", "/v1/contracts/rollups/trader/account");
        ACCOUNTS_BY_ACCOUNT_ID_ASSETS_GET => dataspace_get("application.accounts_by_account_id_assets_get", "/v1/accounts/{account_id}/assets");
        ACCOUNTS_BY_ACCOUNT_ID_ASSETS_QUERY_POST => dataspace_post("application.accounts_by_account_id_assets_query_post", "/v1/accounts/{account_id}/assets/query");
        ACCOUNTS_BY_ACCOUNT_ID_PERMISSIONS_GET => dataspace_get("application.accounts_by_account_id_permissions_get", "/v1/accounts/{account_id}/permissions");
        ACCOUNTS_BY_ACCOUNT_ID_PERMISSIONS_QUERY_POST => dataspace_post("application.accounts_by_account_id_permissions_query_post", "/v1/accounts/{account_id}/permissions/query");
        ACCOUNTS_BY_ACCOUNT_ID_TRANSACTIONS_GET => dataspace_get("application.accounts_by_account_id_transactions_get", "/v1/accounts/{account_id}/transactions");
        ACCOUNTS_BY_ACCOUNT_ID_HISTORY_GET => dataspace_get("application.accounts_by_account_id_history_get", "/v1/accounts/{account_id}/history");
        PROOFS_QUERY_POST => signed_compute_post("application.proofs_query_post", "/v1/proofs/query");
        ZK_PROOF_TAGS_BY_BACKEND_BY_HASH_GET => app_get("application.zk_proof_tags_by_backend_by_hash_get", "/v1/zk/proof-tags/{backend}/{hash}");
        DOMAINS_GET => dataspace_get("application.domains_get", "/v1/domains");
        DOMAINS_QUERY_POST => dataspace_post("application.domains_query_post", "/v1/domains/query");
        ACCOUNTS_GET => dataspace_get("application.accounts_get", "/v1/accounts");
        ACCOUNTS_CAPABILITIES_GET => app_get("application.accounts_capabilities_get", "/v1/accounts/capabilities");
        ACCOUNTS_QUERY_POST => dataspace_post("application.accounts_query_post", "/v1/accounts/query");
        TRANSACTIONS_QUERY_POST => dataspace_post("application.transactions_query_post", "/v1/transactions/query");
        ACCOUNTS_ONBOARD_PLAN_POST => onboarding_compute_post("application.accounts_onboard_plan_post", "/v1/accounts/onboard/plan");
        ACCOUNTS_ONBOARD_PREPARE_POST => onboarding_compute_post("application.accounts_onboard_prepare_post", "/v1/accounts/onboard/prepare");
        ACCOUNTS_ONBOARD_POST => onboarding_post("application.accounts_onboard_post", "/v1/accounts/onboard");
        ACCOUNTS_ONBOARDING_READINESS_GET => onboarding_get("application.accounts_onboarding_readiness_get", "/v1/accounts/onboarding/readiness");
        ACCOUNTS_ONBOARDING_CURRENT_STATE_POST => app_post("application.accounts_onboarding_current_state_post", "/v1/accounts/onboarding/current-state");
        ACCOUNTS_FAUCET_PUZZLE_GET => app_get("application.accounts_faucet_puzzle_get", "/v1/accounts/faucet/puzzle");
        ACCOUNTS_FAUCET_POLICY_GET => app_get("application.accounts_faucet_policy_get", "/v1/accounts/faucet/policy");
        ACCOUNTS_FAUCET_PREPARE_POST => faucet_protocol_compute_post("application.accounts_faucet_prepare_post", "/v1/accounts/faucet/prepare");
        ACCOUNTS_FAUCET_POST => faucet_protocol_mutation_post("application.accounts_faucet_post", "/v1/accounts/faucet");
        ACCOUNTS_BY_ACCOUNT_ID_ALIASES_GET => account_read_sdk_get("application.accounts_by_account_id_aliases_get", "/v1/accounts/{account_id}/aliases");
        ACCOUNTS_BY_UAID_PORTFOLIO_GET => dataspace_get("application.accounts_by_uaid_portfolio_get", "/v1/accounts/{uaid}/portfolio");
        NEXUS_PUBLIC_LANES_BY_LANE_ID_VALIDATORS_GET => app_get("application.nexus_public_lanes_by_lane_id_validators_get", "/v1/nexus/public-lanes/{lane_id}/validators");
        NEXUS_PUBLIC_LANES_BY_LANE_ID_STAKE_GET => app_get("application.nexus_public_lanes_by_lane_id_stake_get", "/v1/nexus/public-lanes/{lane_id}/stake");
        NEXUS_PUBLIC_LANES_BY_LANE_ID_REWARDS_PENDING_GET => app_get("application.nexus_public_lanes_by_lane_id_rewards_pending_get", "/v1/nexus/public-lanes/{lane_id}/rewards/pending");
        NEXUS_DATASPACES_ACCOUNTS_BY_LITERAL_SUMMARY_GET => dataspace_get("application.nexus_dataspaces_accounts_by_literal_summary_get", "/v1/nexus/dataspaces/accounts/{literal}/summary");
        SPACE_DIRECTORY_UAIDS_BY_UAID_GET => dataspace_get("application.space_directory_uaids_by_uaid_get", "/v1/space-directory/uaids/{uaid}");
        SPACE_DIRECTORY_UAIDS_BY_UAID_MANIFESTS_GET => dataspace_get("application.space_directory_uaids_by_uaid_manifests_get", "/v1/space-directory/uaids/{uaid}/manifests");
        SPACE_DIRECTORY_UAIDS_BY_UAID_MANIFESTS_QUERY_POST => dataspace_post("application.space_directory_uaids_by_uaid_manifests_query_post", "/v1/space-directory/uaids/{uaid}/manifests/query");
        SPACE_DIRECTORY_MANIFESTS_POST => account_compute_post("application.space_directory_manifests_post", "/v1/space-directory/manifests");
        SPACE_DIRECTORY_MANIFESTS_REVOKE_POST => account_compute_post("application.space_directory_manifests_revoke_post", "/v1/space-directory/manifests/revoke");
        RAM_LFE_PROGRAM_POLICIES_GET => app_get("application.ram_lfe_program_policies_get", "/v1/ram-lfe/program-policies");
        RAM_LFE_PROGRAMS_BY_PROGRAM_ID_EXECUTE_POST => account_compute_post("application.ram_lfe_programs_by_program_id_execute_post", "/v1/ram-lfe/programs/{program_id}/execute");
        RAM_LFE_RECEIPTS_VERIFY_POST => account_compute_post("application.ram_lfe_receipts_verify_post", "/v1/ram-lfe/receipts/verify");
        IDENTIFIER_POLICIES_GET => app_get("application.identifier_policies_get", "/v1/identifier-policies");
        ACCOUNTS_BY_ACCOUNT_ID_IDENTIFIERS_CLAIM_RECEIPT_POST => account_compute_post("application.accounts_by_account_id_identifiers_claim_receipt_post", "/v1/accounts/{account_id}/identifiers/claim-receipt");
        IDENTIFIERS_RECEIPTS_BY_RECEIPT_HASH_GET => app_get("application.identifiers_receipts_by_receipt_hash_get", "/v1/identifiers/receipts/{receipt_hash}");
        IDENTIFIERS_RESOLVE_POST => account_compute_post("application.identifiers_resolve_post", "/v1/identifiers/resolve");
        REPO_AGREEMENTS_GET => app_get("application.repo_agreements_get", "/v1/repo/agreements");
        REPO_AGREEMENTS_QUERY_POST => account_read_post("application.repo_agreements_query_post", "/v1/repo/agreements/query");
        NOTIFY_DEVICES_POST => push_post("application.notify_devices_post", "/v1/notify/devices");
        NOTIFY_DEVICES_DELETE => push_delete("application.notify_devices_delete", "/v1/notify/devices");
        SNS_NAMES_BY_NAMESPACE_BY_LITERAL_GET => app_get("application.sns_names_by_namespace_by_literal_get", "/v1/sns/names/{namespace}/{literal}");
        SNS_POLICIES_BY_SUFFIX_ID_GET => app_get("application.sns_policies_by_suffix_id_get", "/v1/sns/policies/{suffix_id}");
        SORACLOUD_STATUS_GET => account_read_get("application.soracloud_status_get", "/v1/soracloud/status");
        SORACLOUD_SERVICES_BY_SERVICE_NAME_PUBLIC_DISCOVERY_GET => app_get("application.soracloud_services_by_service_name_public_discovery_get", "/v1/soracloud/services/{service_name}/public-discovery");
        SORACLOUD_SERVICES_BY_SERVICE_NAME_REVISIONS_BY_SERVICE_VERSION_PUBLIC_DISCOVERY_GET => app_get("application.soracloud_services_by_service_name_revisions_by_service_version_public_discovery_get", "/v1/soracloud/services/{service_name}/revisions/{service_version}/public-discovery");
        SORACLOUD_DEPLOY_POST => soracloud_mutation_post("application.soracloud_deploy_post", "/v1/soracloud/deploy");
        SORACLOUD_UPGRADE_POST => soracloud_mutation_post("application.soracloud_upgrade_post", "/v1/soracloud/upgrade");
        SORACLOUD_APPS_DEPLOY_POST => soracloud_mutation_post("application.soracloud_apps_deploy_post", "/v1/soracloud/apps/deploy");
        SORACLOUD_APPS_UPGRADE_POST => soracloud_mutation_post("application.soracloud_apps_upgrade_post", "/v1/soracloud/apps/upgrade");
        SORACLOUD_APPS_STATUS_GET => account_read_sdk_get("application.soracloud_apps_status_get", "/v1/soracloud/apps/status");
        SORACLOUD_APPS_BY_APP_NAME_STATUS_GET => account_read_sdk_get("application.soracloud_apps_by_app_name_status_get", "/v1/soracloud/apps/{app_name}/status");
        SORACLOUD_ROLLBACK_POST => soracloud_mutation_post("application.soracloud_rollback_post", "/v1/soracloud/rollback");
        SORACLOUD_ROLLOUT_POST => soracloud_mutation_post("application.soracloud_rollout_post", "/v1/soracloud/rollout");
        SORACLOUD_STATE_MUTATE_POST => soracloud_mutation_post("application.soracloud_state_mutate_post", "/v1/soracloud/state/mutate");
        SORACLOUD_SERVICE_CONFIG_SET_POST => soracloud_mutation_post("application.soracloud_service_config_set_post", "/v1/soracloud/service/config/set");
        SORACLOUD_SERVICE_CONFIG_DELETE_POST => soracloud_mutation_post("application.soracloud_service_config_delete_post", "/v1/soracloud/service/config/delete");
        SORACLOUD_SERVICE_CONFIG_STATUS_GET => account_read_sdk_get("application.soracloud_service_config_status_get", "/v1/soracloud/service/config/status");
        SORACLOUD_SERVICE_SECRET_SET_POST => soracloud_mutation_post("application.soracloud_service_secret_set_post", "/v1/soracloud/service/secret/set");
        SORACLOUD_SERVICE_SECRET_DELETE_POST => soracloud_mutation_post("application.soracloud_service_secret_delete_post", "/v1/soracloud/service/secret/delete");
        SORACLOUD_SERVICE_SECRET_STATUS_GET => account_read_sdk_get("application.soracloud_service_secret_status_get", "/v1/soracloud/service/secret/status");
        SORACLOUD_FHE_JOB_RUN_POST => soracloud_mutation_post("application.soracloud_fhe_job_run_post", "/v1/soracloud/fhe/job/run");
        SORACLOUD_DECRYPT_REQUEST_POST => soracloud_mutation_post("application.soracloud_decrypt_request_post", "/v1/soracloud/decrypt/request");
        SORACLOUD_HEALTH_ACCESS_REQUEST_POST => soracloud_mutation_post("application.soracloud_health_access_request_post", "/v1/soracloud/health/access/request");
        SORACLOUD_HEALTH_COMPLIANCE_REPORT_GET => account_read_sdk_get("application.soracloud_health_compliance_report_get", "/v1/soracloud/health/compliance/report");
        SORACLOUD_CIPHERTEXT_QUERY_POST => soracloud_read_post("application.soracloud_ciphertext_query_post", "/v1/soracloud/ciphertext/query");
        SORACLOUD_TRAINING_JOB_START_POST => soracloud_mutation_post("application.soracloud_training_job_start_post", "/v1/soracloud/training/job/start");
        SORACLOUD_TRAINING_JOB_CHECKPOINT_POST => soracloud_mutation_post("application.soracloud_training_job_checkpoint_post", "/v1/soracloud/training/job/checkpoint");
        SORACLOUD_TRAINING_JOB_RETRY_POST => soracloud_mutation_post("application.soracloud_training_job_retry_post", "/v1/soracloud/training/job/retry");
        SORACLOUD_TRAINING_JOB_STATUS_GET => account_read_sdk_get("application.soracloud_training_job_status_get", "/v1/soracloud/training/job/status");
        SORACLOUD_MODEL_WEIGHT_REGISTER_POST => soracloud_mutation_post("application.soracloud_model_weight_register_post", "/v1/soracloud/model/weight/register");
        SORACLOUD_MODEL_WEIGHT_PROMOTE_POST => soracloud_mutation_post("application.soracloud_model_weight_promote_post", "/v1/soracloud/model/weight/promote");
        SORACLOUD_MODEL_WEIGHT_ROLLBACK_POST => soracloud_mutation_post("application.soracloud_model_weight_rollback_post", "/v1/soracloud/model/weight/rollback");
        SORACLOUD_MODEL_WEIGHT_STATUS_GET => account_read_sdk_get("application.soracloud_model_weight_status_get", "/v1/soracloud/model/weight/status");
        SORACLOUD_MODEL_ARTIFACT_REGISTER_POST => soracloud_mutation_post("application.soracloud_model_artifact_register_post", "/v1/soracloud/model/artifact/register");
        SORACLOUD_MODEL_ARTIFACT_STATUS_GET => account_read_sdk_get("application.soracloud_model_artifact_status_get", "/v1/soracloud/model/artifact/status");
        SORACLOUD_MODEL_UPLOAD_REGISTER_POST => soracloud_mutation_post("application.soracloud_model_upload_register_post", "/v1/soracloud/model/upload/register");
        SORACLOUD_MODEL_UPLOAD_STATUS_GET => account_read_sdk_get("application.soracloud_model_upload_status_get", "/v1/soracloud/model/upload/status");
        SORACLOUD_HF_SHARED_LEASE_JOIN_POST => soracloud_openapi_mutation_post("application.soracloud_hf_shared_lease_join_post", "/v1/soracloud/hf/lease/join");
        SORACLOUD_HF_SHARED_LEASE_STATUS_GET => account_read_sdk_get("application.soracloud_hf_shared_lease_status_get", "/v1/soracloud/hf/lease/status");
        SORACLOUD_HF_LEASE_LEAVE_POST => soracloud_mutation_post("application.soracloud_hf_lease_leave_post", "/v1/soracloud/hf/lease/leave");
        SORACLOUD_HF_LEASE_RENEW_POST => soracloud_mutation_post("application.soracloud_hf_lease_renew_post", "/v1/soracloud/hf/lease/renew");
        SORACLOUD_AGENT_DEPLOY_POST => soracloud_mutation_post("application.soracloud_agent_deploy_post", "/v1/soracloud/agent/deploy");
        SORACLOUD_AGENT_LEASE_RENEW_POST => soracloud_mutation_post("application.soracloud_agent_lease_renew_post", "/v1/soracloud/agent/lease/renew");
        SORACLOUD_AGENT_RESTART_POST => soracloud_mutation_post("application.soracloud_agent_restart_post", "/v1/soracloud/agent/restart");
        SORACLOUD_AGENT_STATUS_GET => account_read_sdk_get("application.soracloud_agent_status_get", "/v1/soracloud/agent/status");
        SORACLOUD_AGENT_WALLET_SPEND_POST => soracloud_mutation_post("application.soracloud_agent_wallet_spend_post", "/v1/soracloud/agent/wallet/spend");
        SORACLOUD_AGENT_WALLET_APPROVE_POST => soracloud_mutation_post("application.soracloud_agent_wallet_approve_post", "/v1/soracloud/agent/wallet/approve");
        SORACLOUD_AGENT_POLICY_REVOKE_POST => soracloud_mutation_post("application.soracloud_agent_policy_revoke_post", "/v1/soracloud/agent/policy/revoke");
        SORACLOUD_AGENT_MESSAGE_SEND_POST => soracloud_mutation_post("application.soracloud_agent_message_send_post", "/v1/soracloud/agent/message/send");
        SORACLOUD_AGENT_MESSAGE_ACK_POST => soracloud_mutation_post("application.soracloud_agent_message_ack_post", "/v1/soracloud/agent/message/ack");
        SORACLOUD_AGENT_MAILBOX_STATUS_GET => account_read_sdk_get("application.soracloud_agent_mailbox_status_get", "/v1/soracloud/agent/mailbox/status");
        SORACLOUD_AGENT_AUTONOMY_ALLOW_POST => soracloud_mutation_post("application.soracloud_agent_autonomy_allow_post", "/v1/soracloud/agent/autonomy/allow");
        SORACLOUD_AGENT_AUTONOMY_STATUS_GET => account_read_sdk_get("application.soracloud_agent_autonomy_status_get", "/v1/soracloud/agent/autonomy/status");
        ASSETS_DEFINITIONS_GET => dataspace_get("application.assets_definitions_get", "/v1/assets/definitions");
        ASSETS_DEFINITIONS_BY_ASSET_GET => dataspace_get("application.assets_definitions_by_asset_get", "/v1/assets/definitions/{asset}");
        ASSETS_DEFINITIONS_QUERY_POST => dataspace_post("application.assets_definitions_query_post", "/v1/assets/definitions/query");
        CONFIDENTIAL_ASSETS_BY_DEFINITION_ID_TRANSITIONS_GET => app_get("application.confidential_assets_by_definition_id_transitions_get", "/v1/confidential/assets/{definition_id}/transitions");
        NFTS_GET => dataspace_get("application.nfts_get", "/v1/nfts");
        NFTS_QUERY_POST => dataspace_post("application.nfts_query_post", "/v1/nfts/query");
        RWAS_GET => dataspace_get("application.rwas_get", "/v1/rwas");
        RWAS_QUERY_POST => dataspace_post("application.rwas_query_post", "/v1/rwas/query");
        SUBSCRIPTIONS_PLANS_GET => app_get("application.subscriptions_plans_get", "/v1/subscriptions/plans");
        SUBSCRIPTIONS_PLANS_QUERY_POST => app_post("application.subscriptions_plans_query_post", "/v1/subscriptions/plans/query");
        SUBSCRIPTIONS_PLANS_POST => account_mutation_post("application.subscriptions_plans_post", "/v1/subscriptions/plans");
        SUBSCRIPTIONS_GET => app_get("application.subscriptions_get", "/v1/subscriptions");
        SUBSCRIPTIONS_QUERY_POST => app_post("application.subscriptions_query_post", "/v1/subscriptions/query");
        SUBSCRIPTIONS_POST => account_mutation_post("application.subscriptions_post", "/v1/subscriptions");
        SUBSCRIPTIONS_BY_SUBSCRIPTION_ID_GET => app_get("application.subscriptions_by_subscription_id_get", "/v1/subscriptions/{subscription_id}");
        SUBSCRIPTIONS_BY_SUBSCRIPTION_ID_PAUSE_POST => account_mutation_post("application.subscriptions_by_subscription_id_pause_post", "/v1/subscriptions/{subscription_id}/pause");
        SUBSCRIPTIONS_BY_SUBSCRIPTION_ID_RESUME_POST => account_mutation_post("application.subscriptions_by_subscription_id_resume_post", "/v1/subscriptions/{subscription_id}/resume");
        SUBSCRIPTIONS_BY_SUBSCRIPTION_ID_CANCEL_POST => account_mutation_post("application.subscriptions_by_subscription_id_cancel_post", "/v1/subscriptions/{subscription_id}/cancel");
        SUBSCRIPTIONS_BY_SUBSCRIPTION_ID_KEEP_POST => account_mutation_post("application.subscriptions_by_subscription_id_keep_post", "/v1/subscriptions/{subscription_id}/keep");
        SUBSCRIPTIONS_BY_SUBSCRIPTION_ID_USAGE_POST => account_mutation_post("application.subscriptions_by_subscription_id_usage_post", "/v1/subscriptions/{subscription_id}/usage");
        SUBSCRIPTIONS_BY_SUBSCRIPTION_ID_CHARGE_NOW_POST => account_mutation_post("application.subscriptions_by_subscription_id_charge_now_post", "/v1/subscriptions/{subscription_id}/charge-now");
        PARAMETERS_GET => app_get("application.parameters_get", "/v1/parameters");
        EXPLORER_ACCOUNTS_GET => dataspace_get("application.explorer_accounts_get", "/v1/explorer/accounts");
        EXPLORER_ACCOUNTS_QUERY_POST => dataspace_post("application.explorer_accounts_query_post", "/v1/explorer/accounts/query");
        EXPLORER_DOMAINS_GET => dataspace_get("application.explorer_domains_get", "/v1/explorer/domains");
        EXPLORER_DOMAINS_QUERY_POST => dataspace_post("application.explorer_domains_query_post", "/v1/explorer/domains/query");
        EXPLORER_ASSET_DEFINITIONS_GET => dataspace_get("application.explorer_asset_definitions_get", "/v1/explorer/asset-definitions");
        EXPLORER_ASSET_DEFINITIONS_QUERY_POST => dataspace_post("application.explorer_asset_definitions_query_post", "/v1/explorer/asset-definitions/query");
        EXPLORER_ASSETS_GET => dataspace_get("application.explorer_assets_get", "/v1/explorer/assets");
        EXPLORER_ASSETS_QUERY_POST => dataspace_post("application.explorer_assets_query_post", "/v1/explorer/assets/query");
        EXPLORER_NFTS_GET => dataspace_get("application.explorer_nfts_get", "/v1/explorer/nfts");
        EXPLORER_NFTS_QUERY_POST => dataspace_post("application.explorer_nfts_query_post", "/v1/explorer/nfts/query");
        EXPLORER_RWAS_GET => dataspace_get("application.explorer_rwas_get", "/v1/explorer/rwas");
        EXPLORER_RWAS_QUERY_POST => dataspace_post("application.explorer_rwas_query_post", "/v1/explorer/rwas/query");
        EXPLORER_BLOCKS_GET => dataspace_get("application.explorer_blocks_get", "/v1/explorer/blocks");
        EXPLORER_BLOCKS_QUERY_POST => dataspace_post("application.explorer_blocks_query_post", "/v1/explorer/blocks/query");
        EXPLORER_HEALTH_GET => app_sdk_get("application.explorer_health_get", "/v1/explorer/health");
        EXPLORER_BLOCKS_STREAM_GET => dataspace_protocol_get("application.explorer_blocks_stream_get", "/v1/explorer/blocks/stream");
        EXPLORER_TRANSACTIONS_GET => dataspace_get("application.explorer_transactions_get", "/v1/explorer/transactions");
        EXPLORER_TRANSACTIONS_QUERY_POST => dataspace_post("application.explorer_transactions_query_post", "/v1/explorer/transactions/query");
        EXPLORER_TRANSACTIONS_LATEST_GET => dataspace_get("application.explorer_transactions_latest_get", "/v1/explorer/transactions/latest");
        EXPLORER_TRANSACTIONS_LATEST_QUERY_POST => dataspace_post("application.explorer_transactions_latest_query_post", "/v1/explorer/transactions/latest/query");
        EXPLORER_TRANSACTIONS_STREAM_GET => dataspace_protocol_get("application.explorer_transactions_stream_get", "/v1/explorer/transactions/stream");
        EXPLORER_INSTRUCTIONS_GET => dataspace_get("application.explorer_instructions_get", "/v1/explorer/instructions");
        EXPLORER_INSTRUCTIONS_QUERY_POST => dataspace_post("application.explorer_instructions_query_post", "/v1/explorer/instructions/query");
        EXPLORER_INSTRUCTIONS_LATEST_GET => dataspace_get("application.explorer_instructions_latest_get", "/v1/explorer/instructions/latest");
        EXPLORER_INSTRUCTIONS_LATEST_QUERY_POST => dataspace_post("application.explorer_instructions_latest_query_post", "/v1/explorer/instructions/latest/query");
        SORACLES_DEFI_ATTESTATIONS_LATEST_GET => app_sdk_get("application.soracles_defi_attestations_latest_get", "/v1/soracles/defi/attestations/latest");
        SORACLES_FEEDS_GET => app_sdk_get("application.soracles_feeds_get", "/v1/soracles/feeds");
        SORACLES_FEEDS_BY_FEED_ID_HISTORY_GET => app_sdk_get("application.soracles_feeds_by_feed_id_history_get", "/v1/soracles/feeds/{feed_id}/history");
        EXPLORER_METRICS_GET => authenticated_telemetry_documented_get("application.explorer_metrics_get", "/v1/explorer/metrics");
        EXPLORER_INSTRUCTIONS_STREAM_GET => dataspace_telemetry_protocol_get("application.explorer_instructions_stream_get", "/v1/explorer/instructions/stream");
        TELEMETRY_PEERS_INFO_GET => telemetry_documented_get("application.telemetry_peers_info_get", "/v1/telemetry/peers-info");
        TELEMETRY_PROPAGATION_GET => telemetry_diagnostic_get("application.telemetry_propagation_get", "/v1/telemetry/propagation");
        TELEMETRY_LIVE_GET => telemetry_documented_get("application.telemetry_live_get", "/v1/telemetry/live");
        EXPLORER_ACCOUNTS_BY_ACCOUNT_ID_GET => dataspace_get("application.explorer_accounts_by_account_id_get", "/v1/explorer/accounts/{account_id}");
        EXPLORER_ACCOUNTS_BY_ACCOUNT_ID_QR_GET => dataspace_get("application.explorer_accounts_by_account_id_qr_get", "/v1/explorer/accounts/{account_id}/qr");
        EXPLORER_DOMAINS_BY_DOMAIN_ID_GET => dataspace_get("application.explorer_domains_by_domain_id_get", "/v1/explorer/domains/{domain_id}");
        OFFLINE_ASSET_REGISTRATION_GET => dataspace_get("application.offline_asset_registration_get", "/v1/assets/definitions/{asset}/registration");
        EXPLORER_ASSET_DEFINITIONS_BY_DEFINITION_ID_GET => dataspace_get("application.explorer_asset_definitions_by_definition_id_get", "/v1/explorer/asset-definitions/{definition_id}");
        EXPLORER_ASSET_DEFINITIONS_BY_DEFINITION_ID_ECONOMETRICS_GET => dataspace_get("application.explorer_asset_definitions_by_definition_id_econometrics_get", "/v1/explorer/asset-definitions/{definition_id}/econometrics");
        EXPLORER_ASSET_DEFINITIONS_BY_DEFINITION_ID_SNAPSHOT_GET => dataspace_get("application.explorer_asset_definitions_by_definition_id_snapshot_get", "/v1/explorer/asset-definitions/{definition_id}/snapshot");
        EXPLORER_ASSETS_BY_ASSET_ID_GET => dataspace_get("application.explorer_assets_by_asset_id_get", "/v1/explorer/assets/{asset_id}");
        EXPLORER_NFTS_BY_NFT_ID_GET => dataspace_get("application.explorer_nfts_by_nft_id_get", "/v1/explorer/nfts/{nft_id}");
        EXPLORER_RWAS_BY_RWA_ID_GET => dataspace_get("application.explorer_rwas_by_rwa_id_get", "/v1/explorer/rwas/{rwa_id}");
        EXPLORER_BLOCKS_BY_IDENTIFIER_GET => dataspace_get("application.explorer_blocks_by_identifier_get", "/v1/explorer/blocks/{identifier}");
        EXPLORER_TRANSACTIONS_BY_HASH_GET => dataspace_get("application.explorer_transactions_by_hash_get", "/v1/explorer/transactions/{hash}");
        EXPLORER_INSTRUCTIONS_BY_HASH_BY_INDEX_GET => dataspace_get("application.explorer_instructions_by_hash_by_index_get", "/v1/explorer/instructions/{hash}/{index}");
        EXPLORER_INSTRUCTIONS_BY_HASH_BY_INDEX_CONTRACT_VIEW_GET => dataspace_sdk_get("application.explorer_instructions_by_hash_by_index_contract_view_get", "/v1/explorer/instructions/{hash}/{index}/contract-view");
        KAIGI_CALLS_BY_CALL_ID_GET => app_sdk_get("application.kaigi_calls_by_call_id_get", "/v1/kaigi/calls/{call_id}");
        KAIGI_CALLS_BY_CALL_ID_SIGNALS_GET => account_compute_sdk_get("application.kaigi_calls_by_call_id_signals_get", "/v1/kaigi/calls/{call_id}/signals");
        KAIGI_CALLS_BY_CALL_ID_EVENTS_GET => app_unprojected_protocol_get("application.kaigi_calls_by_call_id_events_get", "/v1/kaigi/calls/{call_id}/events");
        KAIGI_RELAYS_GET => operator_expensive_get("application.kaigi_relays_get", "/v1/kaigi/relays");
        KAIGI_RELAYS_BY_RELAY_ID_GET => operator_signed_get("application.kaigi_relays_by_relay_id_get", "/v1/kaigi/relays/{relay_id}");
        KAIGI_RELAYS_HEALTH_GET => operator_expensive_get("application.kaigi_relays_health_get", "/v1/kaigi/relays/health");
        KAIGI_RELAYS_EVENTS_GET => app_protocol_get("application.kaigi_relays_events_get", "/v1/kaigi/relays/events");
        WEBHOOKS_GET => operator_signed_get("application.webhooks_get", "/v1/webhooks");
        WEBHOOKS_POST => operator_signed_post("application.webhooks_post", "/v1/webhooks");
        WEBHOOKS_BY_ID_DELETE => operator_signed_delete("application.webhooks_by_id_delete", "/v1/webhooks/{id}");
    }
}
/// Contract execution, multisig, verification-key, and proof-service routes.
pub mod contracts_and_verification_keys {
    use super::{
        AdmissionPolicy, ApiSurface, AuthenticationPolicy, FeatureGate, HttpMethod, Listener,
        PathPolicy, RouteDescriptor, RouteEffect, RouteProjections, RouteTransport,
    };
    const fn app_get(id: &'static str, path: &'static str) -> RouteDescriptor {
        RouteDescriptor::new(
            id,
            HttpMethod::Get,
            path,
            ApiSurface::Public,
            Listener::Torii,
            RouteEffect::ReadOnly,
            AdmissionPolicy::Public,
        )
        .with_feature_gate(FeatureGate::Feature("app_api"))
        .with_projections(RouteProjections::OPENAPI_AND_SDK)
        .with_cors_options(true)
    }
    const fn app_account_read_get(id: &'static str, path: &'static str) -> RouteDescriptor {
        app_get(id, path)
            .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
            .with_admission(AdmissionPolicy::AuthenticatedAccount)
    }
    const fn app_public_read_post(id: &'static str, path: &'static str) -> RouteDescriptor {
        RouteDescriptor::new(
            id,
            HttpMethod::Post,
            path,
            ApiSurface::Public,
            Listener::Torii,
            RouteEffect::ReadOnly,
            AdmissionPolicy::Public,
        )
        .with_feature_gate(FeatureGate::Feature("app_api"))
        .with_projections(RouteProjections::OPENAPI_AND_SDK)
        .with_cors_options(true)
    }
    const fn app_account_read_post(id: &'static str, path: &'static str) -> RouteDescriptor {
        app_public_read_post(id, path)
            .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
            .with_admission(AdmissionPolicy::AuthenticatedAccount)
    }
    const fn app_account_compute_post(id: &'static str, path: &'static str) -> RouteDescriptor {
        app_account_read_post(id, path).with_effect(RouteEffect::ExpensiveCompute)
    }
    const fn app_account_mutation_post(id: &'static str, path: &'static str) -> RouteDescriptor {
        app_account_read_post(id, path).with_effect(RouteEffect::Mutation)
    }
    const fn app_signed_body_mutation_post(
        id: &'static str,
        path: &'static str,
    ) -> RouteDescriptor {
        app_public_read_post(id, path)
            .with_authentication(AuthenticationPolicy::CanonicalSignedBody)
            .with_effect(RouteEffect::Mutation)
            .with_admission(AdmissionPolicy::AuthenticatedAccount)
    }
    const fn app_unprojected_get(id: &'static str, path: &'static str) -> RouteDescriptor {
        app_get(id, path)
            .with_authentication(AuthenticationPolicy::Unauthenticated)
            .with_projections(RouteProjections::NONE)
    }
    const fn app_unprojected_static_asset_get(
        id: &'static str,
        path: &'static str,
    ) -> RouteDescriptor {
        app_unprojected_get(id, path).with_path_policy(PathPolicy::ProtocolException {
            reason: "browser static asset filename requires a media-type extension",
        })
    }
    const fn app_sdk_get(id: &'static str, path: &'static str) -> RouteDescriptor {
        app_get(id, path).with_projections(RouteProjections::SDK)
    }
    const fn app_account_read_sdk_get(id: &'static str, path: &'static str) -> RouteDescriptor {
        app_account_read_get(id, path).with_projections(RouteProjections::SDK)
    }
    const fn app_account_compute_sdk_post(id: &'static str, path: &'static str) -> RouteDescriptor {
        app_account_compute_post(id, path).with_projections(RouteProjections::SDK)
    }
    const fn app_account_mutation_sdk_post(
        id: &'static str,
        path: &'static str,
    ) -> RouteDescriptor {
        app_account_mutation_post(id, path).with_projections(RouteProjections::SDK)
    }
    const fn app_signed_body_mutation_sdk_post(
        id: &'static str,
        path: &'static str,
    ) -> RouteDescriptor {
        app_signed_body_mutation_post(id, path).with_projections(RouteProjections::SDK)
    }
    const fn app_operator_post(id: &'static str, path: &'static str) -> RouteDescriptor {
        RouteDescriptor::new(
            id,
            HttpMethod::Post,
            path,
            ApiSurface::Operator,
            Listener::Torii,
            RouteEffect::Mutation,
            AdmissionPolicy::Operator,
        )
        .with_authentication(AuthenticationPolicy::OperatorSignature)
        .with_feature_gate(FeatureGate::Feature("app_api"))
        .with_projections(RouteProjections::OPENAPI)
    }
    const fn app_protocol_get(id: &'static str, path: &'static str) -> RouteDescriptor {
        RouteDescriptor::new(
            id,
            HttpMethod::Get,
            path,
            ApiSurface::Protocol,
            Listener::Torii,
            RouteEffect::LongLivedStream,
            AdmissionPolicy::AuthenticatedAccount,
        )
        .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
        .with_transport(RouteTransport::ServerSentEvents)
        .with_feature_gate(FeatureGate::Feature("app_api"))
        .with_projections(RouteProjections::OPENAPI)
        .with_path_policy(PathPolicy::ProtocolException {
            reason: "streaming transport endpoint",
        })
    }
    const fn app_unprojected_protocol_get(id: &'static str, path: &'static str) -> RouteDescriptor {
        app_protocol_get(id, path).with_projections(RouteProjections::NONE)
    }
    const fn app_unprojected_websocket_get(
        id: &'static str,
        path: &'static str,
    ) -> RouteDescriptor {
        app_unprojected_protocol_get(id, path).with_transport(RouteTransport::WebSocket)
    }
    macro_rules! declare_routes {
        ($($name:ident => $factory:ident($id:literal, $path:literal);)+) => {
            $(
                #[doc = concat!("Descriptor for `", $path, "`.")]
                pub const $name: RouteDescriptor = $factory($id, $path);
            )+
            /// Complete contract and verification-key route family.
            pub const ROUTES: &[RouteDescriptor] = &[$($name),+];
        };
    }
    declare_routes! {
        CONTRACTS_ARTIFACTS_BY_DATASPACE_ID_BY_CODE_HASH_BYTES_GET => app_account_read_get("contracts.contracts_artifacts_by_dataspace_id_by_code_hash_bytes_get", "/v1/contracts/artifacts/{dataspace_id}/{code_hash}/bytes");
        CONTRACTS_ALIASES_POST => app_account_mutation_post("contracts.contracts_aliases_post", "/v1/contracts/aliases");
        CONTRACTS_ALIASES_RESOLVE_POST => app_account_read_post("contracts.contracts_aliases_resolve_post", "/v1/contracts/aliases/resolve");
        CONTRACTS_DEPLOYMENT_STATE_POST => app_account_read_post("contracts.contracts_deployment_state_post", "/v1/contracts/deployment-state");
        ASSETS_TRANSFER_POST => app_account_mutation_post("assets.assets_transfer_post", "/v1/assets/transfer");
        CONTRACTS_CALL_POST => app_account_mutation_post("contracts.contracts_call_post", "/v1/contracts/call");
        CONTRACTS_CALL_BATCH_PREPARE_POST => app_account_compute_post("contracts.contracts_call_batch_prepare_post", "/v1/contracts/call/batch/prepare");
        CONTRACTS_CALL_SIMULATE_POST => app_account_compute_post("contracts.contracts_call_simulate_post", "/v1/contracts/call/simulate");
        CONTRACTS_VIEW_POST => app_account_compute_post("contracts.contracts_view_post", "/v1/contracts/view");
        CONTRACTS_VIEW_BATCH_POST => app_account_compute_post("contracts.contracts_view_batch_post", "/v1/contracts/view/batch");
        CONTRACTS_CALL_MULTISIG_PROPOSE_POST => app_account_mutation_post("contracts.contracts_call_multisig_propose_post", "/v1/contracts/call/multisig/propose");
        CONTRACTS_CALL_MULTISIG_APPROVE_POST => app_account_mutation_post("contracts.contracts_call_multisig_approve_post", "/v1/contracts/call/multisig/approve");
        CONTRACTS_STATE_GET => app_get("contracts.contracts_state_get", "/v1/contracts/state");
        MINT_REQUESTS_GET => app_sdk_get("contracts.mint_requests_get", "/v1/mint-requests");
        MINT_REQUESTS_BY_REQUEST_ID_GET => app_sdk_get("contracts.mint_requests_by_request_id_get", "/v1/mint-requests/{request_id}");
        MULTISIG_PROPOSE_POST => app_account_mutation_post("contracts.multisig_propose_post", "/v1/multisig/propose");
        MULTISIG_APPROVE_POST => app_account_mutation_post("contracts.multisig_approve_post", "/v1/multisig/approve");
        MULTISIG_CANCEL_POST => app_account_mutation_post("contracts.multisig_cancel_post", "/v1/multisig/cancel");
        MULTISIG_SPEC_POST => app_account_read_post("contracts.multisig_spec_post", "/v1/multisig/spec");
        MULTISIG_PROPOSALS_QUERY_POST => app_account_read_post("contracts.multisig_proposals_query_post", "/v1/multisig/proposals/query");
        MULTISIG_PROPOSALS_RESOLVE_POST => app_account_read_post("contracts.multisig_proposals_resolve_post", "/v1/multisig/proposals/resolve");
        ACCOUNT_RECOVERY_POLICY_SET_POST => app_account_mutation_post("contracts.account_recovery_policy_set_post", "/v1/accounts/recovery/policy/set");
        ACCOUNT_RECOVERY_PROPOSE_POST => app_account_mutation_post("contracts.account_recovery_propose_post", "/v1/accounts/recovery/propose");
        ACCOUNT_RECOVERY_APPROVE_POST => app_account_mutation_post("contracts.account_recovery_approve_post", "/v1/accounts/recovery/approve");
        ACCOUNT_RECOVERY_FINALIZE_POST => app_account_mutation_post("contracts.account_recovery_finalize_post", "/v1/accounts/recovery/finalize");
        ACCOUNT_RECOVERY_CANCEL_POST => app_account_mutation_post("contracts.account_recovery_cancel_post", "/v1/accounts/recovery/cancel");
        ACCOUNT_RECOVERY_STATUS_POST => app_account_read_post("contracts.account_recovery_status_post", "/v1/accounts/recovery/status");
        CONTROLS_ASSET_TRANSFER_QUERY_POST => app_account_read_post("contracts.controls_asset_transfer_query_post", "/v1/controls/asset-transfer/query");
        ZK_VK_REGISTER_POST => app_account_compute_sdk_post("contracts.zk_vk_register_post", "/v1/zk/vk/register");
        ZK_VK_UPDATE_POST => app_account_compute_sdk_post("contracts.zk_vk_update_post", "/v1/zk/vk/update");
        SORAFS_CAPACITY_DECLARE_POST => app_signed_body_mutation_sdk_post("contracts.sorafs_capacity_declare_post", "/v1/sorafs/capacity/declare");
        SORAFS_CAPACITY_TELEMETRY_POST => app_signed_body_mutation_sdk_post("contracts.sorafs_capacity_telemetry_post", "/v1/sorafs/capacity/telemetry");
        SORAFS_CAPACITY_POR_PROOF_POST => app_operator_post("contracts.sorafs_capacity_por_proof_post", "/v1/sorafs/capacity/por-proof");
        SORAFS_CAPACITY_POR_VERDICT_POST => app_operator_post("contracts.sorafs_capacity_por_verdict_post", "/v1/sorafs/capacity/por-verdict");
        SORAFS_POR_STATUS_GET => app_get("contracts.sorafs_por_status_get", "/v1/sorafs/por/status");
        SORAFS_POR_EXPORT_GET => app_get("contracts.sorafs_por_export_get", "/v1/sorafs/por/export");
        SORAFS_POR_INGESTION_BY_MANIFEST_DIGEST_HEX_GET => app_get("contracts.sorafs_por_ingestion_by_manifest_digest_hex_get", "/v1/sorafs/por/ingestion/{manifest_digest_hex}");
        SORAFS_POR_REPORT_BY_ISO_WEEK_GET => app_get("contracts.sorafs_por_report_by_iso_week_get", "/v1/sorafs/por/report/{iso_week}");
        SORAFS_POR_VRF_POST => app_account_mutation_sdk_post("contracts.sorafs_por_vrf_post", "/v1/sorafs/por/vrf");
        SORAFS_ORDERBOOK_ORDERS_POST => app_signed_body_mutation_sdk_post("contracts.sorafs_orderbook_orders_post", "/v1/sorafs/orderbook/orders");
        SORAFS_ORDERBOOK_CANCEL_POST => app_signed_body_mutation_sdk_post("contracts.sorafs_orderbook_cancel_post", "/v1/sorafs/orderbook/cancel");
        SORAFS_ORDERBOOK_RECEIPTS_POST => app_signed_body_mutation_sdk_post("contracts.sorafs_orderbook_receipts_post", "/v1/sorafs/orderbook/receipts");
        SORAFS_ORDERBOOK_RECEIPTS_GET => app_sdk_get("contracts.sorafs_orderbook_receipts_get", "/v1/sorafs/orderbook/receipts");
        SORAFS_ORDERBOOK_BOOK_GET => app_sdk_get("contracts.sorafs_orderbook_book_get", "/v1/sorafs/orderbook/book");
        SORAFS_ORDERBOOK_TRADES_GET => app_sdk_get("contracts.sorafs_orderbook_trades_get", "/v1/sorafs/orderbook/trades");
        SORAFS_ORDERBOOK_CHANNELS_GET => app_sdk_get("contracts.sorafs_orderbook_channels_get", "/v1/sorafs/orderbook/channels");
        SORAFS_ORDERBOOK_EVENTS_GET => app_sdk_get("contracts.sorafs_orderbook_events_get", "/v1/sorafs/orderbook/events");
        SORAFS_ORDERBOOK_EVENTS_STREAM_GET => app_unprojected_protocol_get("contracts.sorafs_orderbook_events_stream_get", "/v1/sorafs/orderbook/events/stream");
        SORAFS_ORDERBOOK_EVENTS_WS_GET => app_unprojected_websocket_get("contracts.sorafs_orderbook_events_ws_get", "/v1/sorafs/orderbook/events/ws");
        SORAFS_RESERVE_POLICY_GET => app_account_read_sdk_get("contracts.sorafs_reserve_policy_get", "/v1/sorafs/reserve/policy");
        SORAFS_RESERVE_POLICY_PROOF_GET => app_account_read_sdk_get("contracts.sorafs_reserve_policy_proof_get", "/v1/sorafs/reserve/policy/{height}");
        KAGEMUSHA_ENROLLMENT_POST => app_account_mutation_post("contracts.kagemusha_enrollment_post", "/v1/kagemusha/enrollment");
        KAGEMUSHA_LOAD_ISSUANCE_GET => app_account_read_sdk_get("contracts.kagemusha_load_issuance_get", "/v1/kagemusha/{scheme}/wallets/{wallet}/loads/{request}");
        KAGEMUSHA_LOAD_FINALITY_GET => app_account_read_sdk_get("contracts.kagemusha_load_finality_get", "/v1/kagemusha/{scheme}/wallets/{wallet}/loads/{request}/finality");
        KAGEMUSHA_LOAD_EPOCH_GET => app_account_read_sdk_get("contracts.kagemusha_load_epoch_get", "/v1/kagemusha/{scheme}/wallets/{wallet}/loads/{request}/epochs/{boundary}");
        SORAFS_RESERVE_ACCOUNT_PROOF_GET => app_account_read_sdk_get("contracts.sorafs_reserve_account_proof_get", "/v1/sorafs/reserve/providers/{provider_id}/proof/{height}");
        SORAFS_RESERVE_PROVIDERS_GET => app_account_read_sdk_get("contracts.sorafs_reserve_providers_get", "/v1/sorafs/reserve/providers");
        SORAFS_RESERVE_PROVIDERS_BY_PROVIDER_ID_HEX_GET => app_account_read_sdk_get("contracts.sorafs_reserve_providers_by_provider_id_hex_get", "/v1/sorafs/reserve/providers/{provider_id_hex}");
        SORAFS_RESERVE_TOP_UP_POST => app_signed_body_mutation_sdk_post("contracts.sorafs_reserve_top_up_post", "/v1/sorafs/reserve/top-up");
        SORAFS_RESERVE_WITHDRAW_POST => app_signed_body_mutation_sdk_post("contracts.sorafs_reserve_withdraw_post", "/v1/sorafs/reserve/withdraw");
        SORAFS_RESERVE_MOVEMENTS_GET => app_account_read_sdk_get("contracts.sorafs_reserve_movements_get", "/v1/sorafs/reserve/movements");
        SORAFS_RESERVE_MOVEMENTS_BY_MOVEMENT_ID_HEX_GET => app_account_read_sdk_get("contracts.sorafs_reserve_movements_by_movement_id_hex_get", "/v1/sorafs/reserve/movements/{movement_id_hex}");
        SORAFS_RESERVE_MOVEMENTS_BY_MOVEMENT_ID_HEX_DECISION_POST => app_signed_body_mutation_sdk_post("contracts.sorafs_reserve_movements_by_movement_id_hex_decision_post", "/v1/sorafs/reserve/movements/{movement_id_hex}/decision");
        SORAFS_RESERVE_CREDIT_DRAW_POST => app_signed_body_mutation_sdk_post("contracts.sorafs_reserve_credit_draw_post", "/v1/sorafs/reserve/credit/draw");
        SORAFS_RESERVE_CREDIT_REPAY_POST => app_signed_body_mutation_sdk_post("contracts.sorafs_reserve_credit_repay_post", "/v1/sorafs/reserve/credit/repay");
        SORAFS_RESERVE_APPEALS_POST => app_signed_body_mutation_sdk_post("contracts.sorafs_reserve_appeals_post", "/v1/sorafs/reserve/appeals");
        SORAFS_RESERVE_APPEALS_GET => app_account_read_sdk_get("contracts.sorafs_reserve_appeals_get", "/v1/sorafs/reserve/appeals");
        SORAFS_RESERVE_APPEALS_BY_APPEAL_ID_HEX_GET => app_account_read_sdk_get("contracts.sorafs_reserve_appeals_by_appeal_id_hex_get", "/v1/sorafs/reserve/appeals/{appeal_id_hex}");
        SORAFS_RESERVE_APPEALS_BY_APPEAL_ID_HEX_DECISION_POST => app_signed_body_mutation_sdk_post("contracts.sorafs_reserve_appeals_by_appeal_id_hex_decision_post", "/v1/sorafs/reserve/appeals/{appeal_id_hex}/decision");
        SORAFS_RESERVE_EVENTS_GET => app_account_read_sdk_get("contracts.sorafs_reserve_events_get", "/v1/sorafs/reserve/events");
        SORAFS_RESERVE_EVENTS_STREAM_GET => app_unprojected_protocol_get("contracts.sorafs_reserve_events_stream_get", "/v1/sorafs/reserve/events/stream");
        SORAFS_RESERVE_EVENTS_WS_GET => app_unprojected_websocket_get("contracts.sorafs_reserve_events_ws_get", "/v1/sorafs/reserve/events/ws");
        SORAFS_GATEWAY_COMPLIANCE_FEEDS_BY_FEED_ID_GET => app_account_read_get("contracts.sorafs_gateway_compliance_feeds_by_feed_id_get", "/v1/sorafs/gateway/compliance/feeds/{feed_id}");
        SORAFS_GATEWAY_COMPLIANCE_STATUS_GET => app_account_read_get("contracts.sorafs_gateway_compliance_status_get", "/v1/sorafs/gateway/compliance/status");
        SORAFS_GATEWAY_COMPLIANCE_STAGE_POST => app_account_mutation_post("contracts.sorafs_gateway_compliance_stage_post", "/v1/sorafs/gateway/compliance/stage");
        SORAFS_GATEWAY_COMPLIANCE_ACKNOWLEDGE_POST => app_account_mutation_post("contracts.sorafs_gateway_compliance_acknowledge_post", "/v1/sorafs/gateway/compliance/acknowledge");
        SORAFS_GATEWAY_COMPLIANCE_PROMOTE_POST => app_account_mutation_post("contracts.sorafs_gateway_compliance_promote_post", "/v1/sorafs/gateway/compliance/promote");
        SORAFS_GATEWAY_COMPLIANCE_ROLLBACK_POST => app_account_mutation_post("contracts.sorafs_gateway_compliance_rollback_post", "/v1/sorafs/gateway/compliance/rollback");
        SORAFS_APPEALS_PRICING_CONFIG_GET => app_get("contracts.sorafs_appeals_pricing_config_get", "/v1/sorafs/appeals/pricing/config");
        SORAFS_APPEALS_PRICING_STATUS_GET => app_get("contracts.sorafs_appeals_pricing_status_get", "/v1/sorafs/appeals/pricing/status");
        SORAFS_APPEALS_PRICING_QUOTE_POST => app_public_read_post("contracts.sorafs_appeals_pricing_quote_post", "/v1/sorafs/appeals/pricing/quote");
        SORAFS_APPEALS_FINANCE_SETTLE_POST => app_public_read_post("contracts.sorafs_appeals_finance_settle_post", "/v1/sorafs/appeals/finance/settle");
        SORAFS_APPEALS_FINANCE_DISBURSE_POST => app_public_read_post("contracts.sorafs_appeals_finance_disburse_post", "/v1/sorafs/appeals/finance/disburse");
        SORAFS_APPEALS_FINANCE_DEPOSITS_POST => app_account_mutation_post("contracts.sorafs_appeals_finance_deposits_post", "/v1/sorafs/appeals/finance/deposits");
        SORAFS_APPEALS_FINANCE_DEPOSITS_CONFIRM_POST => app_account_read_post("contracts.sorafs_appeals_finance_deposits_confirm_post", "/v1/sorafs/appeals/finance/deposits/confirm");
        SORAFS_APPEALS_FINANCE_DEPOSITS_SETTLE_POST => app_account_read_post("contracts.sorafs_appeals_finance_deposits_settle_post", "/v1/sorafs/appeals/finance/deposits/settle");
        SORAFS_APPEALS_FINANCE_DEPOSITS_SUBMIT_SETTLEMENT_POST => app_account_mutation_post("contracts.sorafs_appeals_finance_deposits_submit_settlement_post", "/v1/sorafs/appeals/finance/deposits/submit-settlement");
        SORAFS_APPEALS_FINANCE_DEPOSITS_RECONCILE_POST => app_account_read_post("contracts.sorafs_appeals_finance_deposits_reconcile_post", "/v1/sorafs/appeals/finance/deposits/reconcile");
        SORAFS_APPEALS_FINANCE_DEPOSITS_BY_ESCROW_ID_HEX_GET => app_account_read_get("contracts.sorafs_appeals_finance_deposits_by_escrow_id_hex_get", "/v1/sorafs/appeals/finance/deposits/{escrow_id_hex}");
        SORAFS_MODERATION_BALLOTS_POST => app_signed_body_mutation_post("contracts.sorafs_moderation_ballots_post", "/v1/sorafs/moderation/ballots");
        SORAFS_MODERATION_BALLOTS_GET => app_get("contracts.sorafs_moderation_ballots_get", "/v1/sorafs/moderation/ballots");
        SORAFS_MODERATION_BALLOTS_BY_CASE_ID_BY_ROUND_ID_GET => app_get("contracts.sorafs_moderation_ballots_by_case_id_by_round_id_get", "/v1/sorafs/moderation/ballots/{case_id}/{round_id}");
        SORAFS_MODERATION_BALLOTS_BY_CASE_ID_BY_ROUND_ID_NO_SHOW_PLAN_GET => app_get("contracts.sorafs_moderation_ballots_by_case_id_by_round_id_no_show_plan_get", "/v1/sorafs/moderation/ballots/{case_id}/{round_id}/no-show-plan");
        SORAFS_MODERATION_BALLOTS_ELIGIBILITY_POST => app_signed_body_mutation_post("contracts.sorafs_moderation_ballots_eligibility_post", "/v1/sorafs/moderation/ballots/eligibility");
        SORAFS_MODERATION_BALLOTS_SORTITION_POST => app_signed_body_mutation_post("contracts.sorafs_moderation_ballots_sortition_post", "/v1/sorafs/moderation/ballots/sortition");
        SORAFS_MODERATION_BALLOTS_ASSIGNMENTS_ACCEPT_POST => app_signed_body_mutation_post("contracts.sorafs_moderation_ballots_assignments_accept_post", "/v1/sorafs/moderation/ballots/assignments/accept");
        SORAFS_MODERATION_BALLOTS_ACTIVATE_POST => app_signed_body_mutation_post("contracts.sorafs_moderation_ballots_activate_post", "/v1/sorafs/moderation/ballots/activate");
        SORAFS_MODERATION_BALLOTS_COMMITS_POST => app_signed_body_mutation_post("contracts.sorafs_moderation_ballots_commits_post", "/v1/sorafs/moderation/ballots/commits");
        SORAFS_MODERATION_BALLOTS_CHALLENGES_POST => app_signed_body_mutation_post("contracts.sorafs_moderation_ballots_challenges_post", "/v1/sorafs/moderation/ballots/challenges");
        SORAFS_MODERATION_BALLOTS_CHALLENGES_RESOLVE_POST => app_signed_body_mutation_post("contracts.sorafs_moderation_ballots_challenges_resolve_post", "/v1/sorafs/moderation/ballots/challenges/resolve");
        SORAFS_MODERATION_BALLOTS_REVEALS_POST => app_signed_body_mutation_post("contracts.sorafs_moderation_ballots_reveals_post", "/v1/sorafs/moderation/ballots/reveals");
        SORAFS_MODERATION_BALLOTS_TALLY_POST => app_signed_body_mutation_post("contracts.sorafs_moderation_ballots_tally_post", "/v1/sorafs/moderation/ballots/tally");
        SORAFS_MODERATION_BALLOTS_EVENTS_GET => app_get("contracts.sorafs_moderation_ballots_events_get", "/v1/sorafs/moderation/ballots/events");
        SORAFS_MODERATION_MODEL_REGISTRY_GET => app_get("contracts.sorafs_moderation_model_registry_get", "/v1/sorafs/moderation/model-registry");
        SORAFS_MODERATION_MODEL_REGISTRY_REPRO_MANIFESTS_POST => app_account_mutation_post("contracts.sorafs_moderation_model_registry_repro_manifests_post", "/v1/sorafs/moderation/model-registry/repro-manifests");
        SORAFS_MODERATION_MODEL_REGISTRY_CORPORA_POST => app_account_mutation_post("contracts.sorafs_moderation_model_registry_corpora_post", "/v1/sorafs/moderation/model-registry/corpora");
        SORAFS_MODERATION_SCREENING_RESULTS_POST => app_account_mutation_post("contracts.sorafs_moderation_screening_results_post", "/v1/sorafs/moderation/screening-results");
        SORAFS_MODERATION_SCREENING_RESULTS_GET => app_get("contracts.sorafs_moderation_screening_results_get", "/v1/sorafs/moderation/screening-results");
        SORAFS_MODERATION_DEAD_LETTERS_PREPARE_POST => app_account_mutation_post("contracts.sorafs_moderation_dead_letters_prepare_post", "/v1/sorafs/moderation/dead-letters/prepare");
        SORAFS_MODERATION_DEAD_LETTERS_APPLY_POST => app_account_mutation_post("contracts.sorafs_moderation_dead_letters_apply_post", "/v1/sorafs/moderation/dead-letters/apply");
        SORAFS_MODERATION_QUARANTINE_GET => app_get("contracts.sorafs_moderation_quarantine_get", "/v1/sorafs/moderation/quarantine");
        SORAFS_MODERATION_QUARANTINE_BY_QUARANTINE_ID_HEX_REVIEW_POST => app_account_mutation_post("contracts.sorafs_moderation_quarantine_by_quarantine_id_hex_review_post", "/v1/sorafs/moderation/quarantine/{quarantine_id_hex}/review");
        SORAFS_MODERATION_QUARANTINE_BY_QUARANTINE_ID_HEX_RELEASE_POST => app_account_mutation_post("contracts.sorafs_moderation_quarantine_by_quarantine_id_hex_release_post", "/v1/sorafs/moderation/quarantine/{quarantine_id_hex}/release");
        SORAFS_MODERATION_QUARANTINE_BY_QUARANTINE_ID_HEX_APPEAL_HANDOFF_POST => app_account_compute_post("contracts.sorafs_moderation_quarantine_by_quarantine_id_hex_appeal_handoff_post", "/v1/sorafs/moderation/quarantine/{quarantine_id_hex}/appeal-handoff");
        SORAFS_MODERATION_QUARANTINE_BY_QUARANTINE_ID_HEX_OPERATOR_PANEL_GET => app_account_read_get("contracts.sorafs_moderation_quarantine_by_quarantine_id_hex_operator_panel_get", "/v1/sorafs/moderation/quarantine/{quarantine_id_hex}/operator-panel");
        SORAFS_MODERATION_QUARANTINE_BY_QUARANTINE_ID_HEX_OBJECT_POST => app_account_mutation_post("contracts.sorafs_moderation_quarantine_by_quarantine_id_hex_object_post", "/v1/sorafs/moderation/quarantine/{quarantine_id_hex}/object");
        SORAFS_MODERATION_QUARANTINE_BY_QUARANTINE_ID_HEX_OBJECT_GET => app_account_read_get("contracts.sorafs_moderation_quarantine_by_quarantine_id_hex_object_get", "/v1/sorafs/moderation/quarantine/{quarantine_id_hex}/object");
        EVIDENCE_SESSION_CHALLENGE_POST => app_account_mutation_post("contracts.evidence_session_challenge_post", "/v1/evidence/session/challenge");
        EVIDENCE_SESSION_POST => app_account_mutation_post("contracts.evidence_session_post", "/v1/evidence/session");
        EVIDENCE_MANIFEST_BY_SESSION_ID_HEX_GET => app_account_read_get("contracts.evidence_manifest_by_session_id_hex_get", "/v1/evidence/manifest/{session_id_hex}");
        EVIDENCE_SEGMENT_BY_SESSION_ID_HEX_GET => app_account_read_get("contracts.evidence_segment_by_session_id_hex_get", "/v1/evidence/segment/{session_id_hex}");
        EVIDENCE_LOG_BY_SESSION_ID_HEX_POST => app_account_mutation_post("contracts.evidence_log_by_session_id_hex_post", "/v1/evidence/log/{session_id_hex}");
        EVIDENCE_AUDIT_GET => app_account_read_get("contracts.evidence_audit_get", "/v1/evidence/audit");
        EVIDENCE_STATUS_GET => app_account_read_get("contracts.evidence_status_get", "/v1/evidence/status");
        EVIDENCE_LEGAL_HOLD_POST => app_account_mutation_post("contracts.evidence_legal_hold_post", "/v1/evidence/legal-hold");
        EVIDENCE_LEGAL_HOLD_BY_HOLD_ID_HEX_RELEASE_POST => app_account_mutation_post("contracts.evidence_legal_hold_by_hold_id_hex_release_post", "/v1/evidence/legal-hold/{hold_id_hex}/release");
        EVIDENCE_RETENTION_GET => app_account_read_get("contracts.evidence_retention_get", "/v1/evidence/retention");
        EVIDENCE_RETENTION_POST => app_account_mutation_post("contracts.evidence_retention_post", "/v1/evidence/retention");
        EVIDENCE_ERASURE_POST => app_account_mutation_post("contracts.evidence_erasure_post", "/v1/evidence/erasure");
        EVIDENCE_VIEWER_GET => app_unprojected_get("contracts.evidence_viewer_get", "/v1/evidence/viewer");
        EVIDENCE_VIEWER_CSS_GET => app_unprojected_static_asset_get("contracts.evidence_viewer_css_get", "/v1/evidence/viewer/app.css");
        EVIDENCE_VIEWER_JS_GET => app_unprojected_static_asset_get("contracts.evidence_viewer_js_get", "/v1/evidence/viewer/app.js");
        SORAFS_AUDIT_REPAIR_REPORT_POST => app_signed_body_mutation_post("contracts.sorafs_audit_repair_report_post", "/v1/sorafs/audit/repair/report");
        SORAFS_AUDIT_REPAIR_SLASH_POST => app_signed_body_mutation_post("contracts.sorafs_audit_repair_slash_post", "/v1/sorafs/audit/repair/slash");
        SORAFS_AUDIT_REPAIR_CLAIM_POST => app_signed_body_mutation_post("contracts.sorafs_audit_repair_claim_post", "/v1/sorafs/audit/repair/claim");
        SORAFS_AUDIT_REPAIR_HEARTBEAT_POST => app_signed_body_mutation_post("contracts.sorafs_audit_repair_heartbeat_post", "/v1/sorafs/audit/repair/heartbeat");
        SORAFS_AUDIT_REPAIR_COMPLETE_POST => app_signed_body_mutation_post("contracts.sorafs_audit_repair_complete_post", "/v1/sorafs/audit/repair/complete");
        SORAFS_AUDIT_REPAIR_FAIL_POST => app_signed_body_mutation_post("contracts.sorafs_audit_repair_fail_post", "/v1/sorafs/audit/repair/fail");
        SORAFS_AUDIT_REPAIR_APPEAL_POST => app_signed_body_mutation_post("contracts.sorafs_audit_repair_appeal_post", "/v1/sorafs/audit/repair/appeal");
        SORAFS_AUDIT_REPAIR_STATUS_GET => app_get("contracts.sorafs_audit_repair_status_get", "/v1/sorafs/audit/repair/status");
        SORAFS_AUDIT_REPAIR_TASKS_GET => app_get("contracts.sorafs_audit_repair_tasks_get", "/v1/sorafs/audit/repair/tasks");
        SORAFS_AUDIT_REPAIR_TASKS_BY_TICKET_ID_GET => app_get("contracts.sorafs_audit_repair_tasks_by_ticket_id_get", "/v1/sorafs/audit/repair/tasks/{ticket_id}");
        SORAFS_AUDIT_REPAIR_EVENTS_GET => app_get("contracts.sorafs_audit_repair_events_get", "/v1/sorafs/audit/repair/events");
        ZK_VK_BY_BACKEND_BY_NAME_GET => app_get("contracts.zk_vk_by_backend_by_name_get", "/v1/zk/vk/{backend}/{name}");
        ZK_VK_GET => app_get("contracts.zk_vk_get", "/v1/zk/vk");
        ZK_PROOFS_GET => app_get("contracts.zk_proofs_get", "/v1/zk/proofs");
        ZK_PROOFS_COUNT_GET => app_get("contracts.zk_proofs_count_get", "/v1/zk/proofs/count");
        ZK_PROOF_BY_BACKEND_BY_HASH_GET => app_get("contracts.zk_proof_by_backend_by_hash_get", "/v1/zk/proof/{backend}/{hash}");
        CONTRACTS_ARTIFACTS_BY_DATASPACE_ID_BY_CODE_HASH_GET => app_account_read_get("contracts.contracts_artifacts_by_dataspace_id_by_code_hash_get", "/v1/contracts/artifacts/{dataspace_id}/{code_hash}");
        CONTRACTS_ARTIFACTS_BY_DATASPACE_ID_BY_CODE_HASH_CONTRACT_VIEW_GET => app_account_read_sdk_get("contracts.contracts_artifacts_by_dataspace_id_by_code_hash_contract_view_get", "/v1/contracts/artifacts/{dataspace_id}/{code_hash}/contract-view");
        CONTRACTS_ARTIFACTS_BY_DATASPACE_ID_BY_CODE_HASH_VERIFIED_SOURCE_JOBS_POST => app_account_mutation_sdk_post("contracts.contracts_artifacts_by_dataspace_id_by_code_hash_verified_source_jobs_post", "/v1/contracts/artifacts/{dataspace_id}/{code_hash}/verified-source/jobs");
        CONTRACTS_ARTIFACTS_BY_DATASPACE_ID_BY_CODE_HASH_VERIFIED_SOURCE_JOBS_BY_JOB_ID_GET => app_account_read_sdk_get("contracts.contracts_artifacts_by_dataspace_id_by_code_hash_verified_source_jobs_by_job_id_get", "/v1/contracts/artifacts/{dataspace_id}/{code_hash}/verified-source-jobs/{job_id}");
    }
}
/// Protocol-native `SoraCloud` public gateway routes.
pub mod soracloud_gateway {
    use super::{
        AdmissionPolicy, ApiSurface, AuthenticationPolicy, FeatureGate, HttpMethod, Listener,
        PathPolicy, RouteDescriptor, RouteEffect, RouteMatch,
    };
    /// Forward the root path for a local `SoraCloud` public runtime.
    pub const LOCAL_ROOT: RouteDescriptor = RouteDescriptor::new(
        "protocol.soracloud.local_root",
        HttpMethod::Any,
        "/api",
        ApiSurface::Protocol,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_authentication(AuthenticationPolicy::Unauthenticated)
    .with_feature_gate(FeatureGate::Feature("app_api"))
    .with_path_policy(PathPolicy::ProtocolException {
        reason: "public SoraCloud runtime gateway",
    });
    /// Forward a path under a local `SoraCloud` public runtime.
    pub const LOCAL_PATH: RouteDescriptor = RouteDescriptor::new(
        "protocol.soracloud.local_path",
        HttpMethod::Any,
        "/api/{*tail}",
        ApiSurface::Protocol,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_authentication(AuthenticationPolicy::Unauthenticated)
    .with_feature_gate(FeatureGate::Feature("app_api"))
    .with_route_match(RouteMatch::Wildcard)
    .with_path_policy(PathPolicy::ProtocolException {
        reason: "public SoraCloud runtime gateway wildcard",
    });
    /// Canonical public-runtime gateway route set.
    pub const ROUTES: &[RouteDescriptor] = &[LOCAL_ROOT, LOCAL_PATH];
}
/// Raw content and `SoraDNS` directory routes.
pub mod content_directory {
    use super::{
        AdmissionPolicy, ApiSurface, AuthenticationPolicy, FeatureGate, HttpMethod, Listener,
        RouteDescriptor, RouteEffect, RouteMatch, RouteProjections,
    };
    /// Read one path from a registered content bundle.
    pub const CONTENT: RouteDescriptor = RouteDescriptor::new(
        "protocol.content.read",
        HttpMethod::Get,
        "/v1/content/{bundle}/{*path}",
        ApiSurface::Protocol,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_authentication(AuthenticationPolicy::ManifestConditionalContent)
    .with_feature_gate(FeatureGate::Feature("app_api"))
    .with_projections(RouteProjections::OPENAPI)
    .with_route_match(RouteMatch::Wildcard)
    .with_cors_options(true);
    /// Read the latest signed `SoraDNS` directory snapshot.
    pub const SORADNS_LATEST: RouteDescriptor = RouteDescriptor::new(
        "soradns.directory.latest",
        HttpMethod::Get,
        "/v1/soradns/directory/latest",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_feature_gate(FeatureGate::Feature("app_api"))
    .with_projections(RouteProjections::OPENAPI)
    .with_cors_options(true);
    /// Read the bounded `SoraDNS` directory event snapshot.
    pub const SORADNS_EVENTS: RouteDescriptor = RouteDescriptor::new(
        "soradns.directory.events",
        HttpMethod::Get,
        "/v1/soradns/directory/events",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_feature_gate(FeatureGate::Feature("app_api"))
    .with_projections(RouteProjections::OPENAPI)
    .with_cors_options(true);
    /// Canonical raw-content and directory route set.
    pub const ROUTES: &[RouteDescriptor] = &[CONTENT, SORADNS_LATEST, SORADNS_EVENTS];
}
/// SCCP v1 public read API (`specs/sccp.md` §6): every peer serves identical bytes derived from
/// committed state, and readers verify every proof themselves.
pub mod sccp {
    use super::{
        AdmissionPolicy, ApiSurface, HttpMethod, Listener, RouteDescriptor, RouteEffect,
        RouteProjections,
    };
    const fn public_get(stable_route_id: &'static str, path: &'static str) -> RouteDescriptor {
        RouteDescriptor::new(
            stable_route_id,
            HttpMethod::Get,
            path,
            ApiSurface::Public,
            Listener::Torii,
            RouteEffect::ReadOnly,
            AdmissionPolicy::Public,
        )
        .with_projections(RouteProjections::OPENAPI)
        .with_cors_options(true)
    }
    /// Read the Taira identity, parameters and attestation health.
    pub const CAPABILITIES: RouteDescriptor =
        public_get("sccp.capabilities.read", "/v1/sccp/capabilities");
    /// Read every route with its escrow, stranded balance and revisions.
    pub const REGISTRY: RouteDescriptor = public_get("sccp.registry.read", "/v1/sccp/registry");
    /// Read the status union of one message id (outbound, inbound or unknown).
    pub const MESSAGE: RouteDescriptor =
        public_get("sccp.message.read", "/v1/sccp/messages/{message_id}");
    /// Read the newest outbound or inbound records.
    pub const MESSAGES_RECENT: RouteDescriptor =
        public_get("sccp.messages.recent", "/v1/sccp/messages/recent");
    /// Read the outbound records of one route revision by nonce.
    pub const OUTBOUND_BY_NONCE: RouteDescriptor = public_get(
        "sccp.outbound.by_nonce",
        "/v1/sccp/outbound/{network}/{revision}",
    );
    /// Read the destination controls of one route revision.
    pub const CONTROLS: RouteDescriptor = public_get(
        "sccp.controls.list",
        "/v1/sccp/controls/{network}/{revision}",
    );
    /// Assemble the attestation proof bundle of one outbound message.
    pub const MESSAGE_PROOF: RouteDescriptor =
        public_get("sccp.message.proof", "/v1/sccp/messages/{message_id}/proof");
    /// Assemble the attestation proof bundle of one destination control.
    pub const CONTROL_PROOF: RouteDescriptor = public_get(
        "sccp.control.proof",
        "/v1/sccp/controls/{network}/{revision}/{control_nonce}/proof",
    );
    /// Read the current roster generation.
    pub const ROSTER_CURRENT: RouteDescriptor =
        public_get("sccp.roster.current", "/v1/sccp/rosters/current");
    /// Assemble the catch-up rotation chain from a generation.
    pub const ROSTER_ROTATIONS: RouteDescriptor =
        public_get("sccp.roster.rotations", "/v1/sccp/rosters/rotations");
    /// Read one roster generation.
    pub const ROSTER: RouteDescriptor =
        public_get("sccp.roster.read", "/v1/sccp/rosters/{generation}");
    /// Read every installed inbound light client.
    pub const LIGHT_CLIENTS: RouteDescriptor =
        public_get("sccp.light_client.list", "/v1/sccp/light-clients");
    /// Read one inbound light client with its freshness and stored data.
    pub const LIGHT_CLIENT: RouteDescriptor =
        public_get("sccp.light_client.read", "/v1/sccp/light-clients/{network}");
    /// Read the stored consensus sets of one inbound light client.
    pub const LIGHT_CLIENT_SETS: RouteDescriptor = public_get(
        "sccp.light_client.sets",
        "/v1/sccp/light-clients/{network}/sets",
    );
    /// Read the stored checkpoints anchoring a proof of one source height.
    pub const LIGHT_CLIENT_CHECKPOINTS: RouteDescriptor = public_get(
        "sccp.light_client.checkpoints",
        "/v1/sccp/light-clients/{network}/checkpoints",
    );
    /// Read the history path of one SCCP block.
    pub const HISTORY: RouteDescriptor =
        public_get("sccp.history.proof", "/v1/sccp/history/{height}");
    /// Read the per-subject SCCP governance revisions.
    pub const GOVERNANCE: RouteDescriptor =
        public_get("sccp.governance.read", "/v1/sccp/governance");
    /// Read every open SCCP governance proposal with its newest Parliament attempt.
    pub const GOVERNANCE_PROPOSALS: RouteDescriptor =
        public_get("sccp.governance.proposals", "/v1/sccp/governance/proposals");
    /// Read one SCCP governance proposal in any phase.
    pub const GOVERNANCE_PROPOSAL: RouteDescriptor = public_get(
        "sccp.governance.proposal",
        "/v1/sccp/governance/proposals/{proposal_id}",
    );
    /// Complete SCCP read route set.
    pub const ROUTES: &[RouteDescriptor] = &[
        CAPABILITIES,
        GOVERNANCE,
        GOVERNANCE_PROPOSALS,
        GOVERNANCE_PROPOSAL,
        HISTORY,
        LIGHT_CLIENTS,
        LIGHT_CLIENT,
        LIGHT_CLIENT_SETS,
        LIGHT_CLIENT_CHECKPOINTS,
        REGISTRY,
        MESSAGES_RECENT,
        MESSAGE,
        MESSAGE_PROOF,
        OUTBOUND_BY_NONCE,
        CONTROLS,
        CONTROL_PROOF,
        ROSTER_CURRENT,
        ROSTER_ROTATIONS,
        ROSTER,
    ];
}
/// Canonical descriptors enforced by Torii's mounted-route registry. Router assembly fails when any
/// enabled descriptor is missing or when a registration does not match this catalog exactly.
const CATALOGED_ROUTE_FAMILIES: &[&[RouteDescriptor]] = &[
    aliases::ROUTES,
    fees::ROUTES,
    operator_authentication::ROUTES,
    core::INFO_ROUTES,
    core::TIME_ROUTES,
    diagnostic::ROUTES,
    pipeline::ROUTES,
    iso20022::ROUTES,
    data_availability::ROUTES,
    musubi::ROUTES,
    private_settlement::ROUTES,
    streaming::APP_ROUTES,
    mcp_transport::ROUTES,
    connect::ROUTES,
    telemetry::ROUTES,
    sumeragi::ROUTES,
    runtime_governance::ROUTES,
    sorafs::ROUTES,
    application_api::ROUTES,
    contracts_and_verification_keys::ROUTES,
    soracloud_gateway::ROUTES,
    content_directory::ROUTES,
    multisig_execution_evidence::ROUTES,
    sccp::ROUTES,
];
const fn cataloged_route_count(families: &[&[RouteDescriptor]]) -> usize {
    let mut count = 0;
    let mut family_index = 0;
    while family_index < families.len() {
        count += families[family_index].len();
        family_index += 1;
    }
    count
}
const CATALOGED_ROUTE_COUNT: usize = cataloged_route_count(CATALOGED_ROUTE_FAMILIES);
static CATALOGED_ROUTE_STORAGE: [RouteDescriptor; CATALOGED_ROUTE_COUNT] = {
    let mut routes = [aliases::SETUP_PLAN; CATALOGED_ROUTE_COUNT];
    let mut output_index = 0;
    let mut family_index = 0;
    while family_index < CATALOGED_ROUTE_FAMILIES.len() {
        let family = CATALOGED_ROUTE_FAMILIES[family_index];
        let mut route_index = 0;
        while route_index < family.len() {
            routes[output_index] = family[route_index];
            output_index += 1;
            route_index += 1;
        }
        family_index += 1;
    }
    routes
};
/// Canonical descriptors enforced by Torii's mounted-route registry.
///
/// Router assembly fails when any enabled descriptor is missing or when a
/// registration does not match this catalog exactly.
pub const CATALOGED_ROUTES: &[RouteDescriptor] = &CATALOGED_ROUTE_STORAGE;
include!("route_catalog/tests.rs");
