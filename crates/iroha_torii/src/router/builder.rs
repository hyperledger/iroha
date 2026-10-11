//! Catalog-enforced Torii router composition.
//!
//! The builder records the exact descriptor for every cataloged mount. Its
//! manifest is independent of Axum internals: validation never parses router
//! debug output and never scans source text.
use crate::{SharedAppState, operator_signatures};
use axum::{
    Router,
    body::Body,
    handler::Handler,
    http::{HeaderValue, Method, Request},
    response::IntoResponse,
    routing::{MethodFilter, MethodRouter, Route, any, delete, on, post},
};
use iroha_torii_shared::route_catalog::{
    AdmissionPolicy, ApiSurface, AuthenticationPolicy, CatalogProjection, CatalogValidationError,
    EnabledFeatures, HttpMethod, ImplicitRouteDescriptor, Listener, RouteCatalog, RouteDescriptor,
    RouteEffect, RouteProjections, RouteTransport,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
    sync::Arc,
};
use tower::{Layer, Service};
const COMPILED_ROUTE_FEATURES: &[&str] = &[
    #[cfg(feature = "app_api")]
    "app_api",
    #[cfg(feature = "telemetry")]
    "telemetry",
    #[cfg(feature = "profiling")]
    "profiling",
    #[cfg(feature = "schema")]
    "schema",
    #[cfg(feature = "connect")]
    "connect",
    #[cfg(feature = "zk-verify-batch")]
    "zk-verify-batch",
    #[cfg(feature = "push")]
    "push",
    #[cfg(feature = "test-network-private-settlement-route-control")]
    "test-network-private-settlement-route-control",
];
/// Return the Cargo features relevant to canonical route projection.
#[must_use]
pub(crate) const fn compiled_route_features() -> EnabledFeatures<'static> {
    EnabledFeatures::new(COMPILED_ROUTE_FEATURES)
}
/// Complete description of what one composed router mounted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MountedRouteManifest {
    explicit_routes: Vec<RouteDescriptor>,
    implicit_routes: Vec<ImplicitRouteDescriptor>,
}
/// Stable metadata for the route selected by Axum.
///
/// The route identifier and template come from the catalog. Framework misses
/// use fixed bounded identifiers and never copy the raw request URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MatchedRouteMetadata {
    stable_route_id: &'static str,
    path_template: Arc<str>,
    surface: Option<ApiSurface>,
    listener: Option<Listener>,
    effect: Option<RouteEffect>,
    admission: Option<AdmissionPolicy>,
    transport: Option<RouteTransport>,
    private_no_store: bool,
    projections: RouteProjections,
}
impl MatchedRouteMetadata {
    /// Metadata used when no router template was selected.
    #[must_use]
    pub(crate) fn unmatched() -> Self {
        Self::framework(
            "http.route_not_found",
            "unmatched",
            None,
            None,
            None,
            None,
            false,
        )
    }
    /// Stable, bounded route identifier suitable for logs and metric labels.
    #[must_use]
    pub(crate) const fn stable_route_id(&self) -> &'static str {
        self.stable_route_id
    }
    /// Router template selected by Axum, never the raw request path.
    #[must_use]
    pub(crate) fn path_template(&self) -> &str {
        &self.path_template
    }
    /// Security/audience surface, when the route is cataloged.
    #[must_use]
    pub(crate) const fn surface(&self) -> Option<ApiSurface> {
        self.surface
    }
    /// Listener projection, when the route is cataloged.
    #[must_use]
    pub(crate) const fn listener(&self) -> Option<Listener> {
        self.listener
    }
    /// Server-side effect classification, when the route is cataloged.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn effect(&self) -> Option<RouteEffect> {
        self.effect
    }
    /// Principal admission requirement, when the route is cataloged.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn admission(&self) -> Option<AdmissionPolicy> {
        self.admission
    }
    /// Application transport selected by an exact catalog operation.
    ///
    /// Framework responses such as 404, 405, and CORS preflight return
    /// `None`; callers must treat them as ordinary HTTP rather than inheriting
    /// a streaming transport from another method at the same path.
    #[must_use]
    pub(crate) const fn transport(&self) -> Option<RouteTransport> {
        self.transport
    }
    /// Whether the catalog requires every response to be private and non-cacheable.
    #[must_use]
    pub(crate) const fn requires_private_no_store(&self) -> bool {
        self.private_no_store
    }
    /// Documentation/tooling projections declared by the catalog.
    #[must_use]
    pub(crate) const fn projections(&self) -> RouteProjections {
        self.projections
    }
    /// Build metadata from an exact mounted catalog descriptor.
    pub(crate) fn from_descriptor(descriptor: RouteDescriptor) -> Self {
        Self {
            stable_route_id: descriptor.stable_route_id(),
            path_template: Arc::from(descriptor.path()),
            surface: Some(descriptor.surface()),
            listener: Some(descriptor.listener()),
            effect: Some(descriptor.effect()),
            admission: Some(descriptor.admission()),
            transport: Some(descriptor.transport()),
            private_no_store: descriptor.requires_private_no_store(),
            projections: descriptor.projections(),
        }
    }
    /// Build bounded framework metadata for a method rejected by one selected
    /// route descriptor.
    ///
    /// Host-selected routes are resolved outside Axum's path matcher, but a
    /// rejected method must retain the same public surface and cache policy as
    /// the selected route without pretending that its operation ran.
    pub(crate) fn method_not_allowed_for(descriptor: RouteDescriptor) -> Self {
        Self::framework(
            "http.method_not_allowed",
            descriptor.path(),
            Some(descriptor.surface()),
            Some(descriptor.listener()),
            Some(descriptor.effect()),
            Some(descriptor.admission()),
            descriptor.requires_private_no_store(),
        )
    }
    fn framework(
        stable_route_id: &'static str,
        path_template: impl Into<Arc<str>>,
        surface: Option<ApiSurface>,
        listener: Option<Listener>,
        effect: Option<RouteEffect>,
        admission: Option<AdmissionPolicy>,
        private_no_store: bool,
    ) -> Self {
        Self {
            stable_route_id,
            path_template: path_template.into(),
            surface,
            listener,
            effect,
            admission,
            transport: None,
            private_no_store,
            projections: RouteProjections::NONE,
        }
    }
}
/// Immutable lookup used to attach catalog metadata after Axum has selected a
/// route template.
#[derive(Debug, Clone)]
pub(crate) struct MountedRouteIndex {
    explicit: Arc<BTreeMap<(&'static str, &'static str), RouteDescriptor>>,
    by_path: Arc<BTreeMap<&'static str, RouteDescriptor>>,
    allow_by_path: Arc<BTreeMap<&'static str, HeaderValue>>,
    private_no_store_paths: Arc<BTreeSet<&'static str>>,
    cors_paths: Arc<BTreeSet<&'static str>>,
}
impl MountedRouteIndex {
    /// Resolve one selected method/template pair without consulting the raw URI.
    #[must_use]
    pub(crate) fn resolve(
        &self,
        method: &Method,
        matched_path: Option<&str>,
    ) -> MatchedRouteMetadata {
        let Some(path_template) = matched_path else {
            return MatchedRouteMetadata::unmatched();
        };
        if let Some(descriptor) = self.explicit.get(&(method.as_str(), path_template)) {
            return MatchedRouteMetadata::from_descriptor(*descriptor);
        }
        if let Some(descriptor) = self.explicit.get(&("ANY", path_template)) {
            return MatchedRouteMetadata::from_descriptor(*descriptor);
        }
        if method == Method::OPTIONS && self.cors_paths.contains(path_template) {
            let descriptor = self.by_path.get(path_template).copied();
            let private_no_store = self.private_no_store_paths.contains(path_template);
            return MatchedRouteMetadata::framework(
                "http.cors_preflight",
                Arc::<str>::from(path_template),
                descriptor.map(RouteDescriptor::surface),
                descriptor.map(RouteDescriptor::listener),
                descriptor.map(RouteDescriptor::effect),
                descriptor.map(RouteDescriptor::admission),
                private_no_store,
            );
        }
        if let Some(descriptor) = self.by_path.get(path_template) {
            let private_no_store = self.private_no_store_paths.contains(path_template);
            return MatchedRouteMetadata::framework(
                "http.method_not_allowed",
                Arc::<str>::from(path_template),
                Some(descriptor.surface()),
                Some(descriptor.listener()),
                Some(descriptor.effect()),
                Some(descriptor.admission()),
                private_no_store,
            );
        }
        // Axum selected a path absent from the immutable mounted index. Keep
        // the label bounded; completeness tests make this an invariant failure
        // rather than an alternate registration path.
        MatchedRouteMetadata::framework(
            "catalog.unregistered",
            Arc::<str>::from(path_template),
            None,
            None,
            None,
            None,
            false,
        )
    }
}
impl MountedRouteManifest {
    /// Explicit application operations, in canonical catalog order.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn explicit_routes(&self) -> &[RouteDescriptor] {
        &self.explicit_routes
    }
    /// Framework-level CORS OPTIONS behavior.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn implicit_routes(&self) -> &[ImplicitRouteDescriptor] {
        &self.implicit_routes
    }
    /// Build the immutable matched-route lookup used by request middleware.
    #[must_use]
    pub(crate) fn route_index(&self) -> MountedRouteIndex {
        let explicit = self
            .explicit_routes
            .iter()
            .map(|descriptor| {
                (
                    (descriptor.method().as_str(), descriptor.path()),
                    *descriptor,
                )
            })
            .collect();
        let by_path = self
            .explicit_routes
            .iter()
            .map(|descriptor| (descriptor.path(), *descriptor))
            .collect();
        // The completed manifest is also the sole Allow-header authority.
        // Build each immutable value once; method rejection does not scan the
        // catalog or allocate a joined string on the request path.
        let mut methods_by_path = BTreeMap::<_, BTreeSet<_>>::new();
        for descriptor in &self.explicit_routes {
            if descriptor.method() != HttpMethod::Any {
                methods_by_path
                    .entry(descriptor.path())
                    .or_default()
                    .insert(descriptor.method().as_str());
            }
        }
        let allow_by_path = methods_by_path
            .into_iter()
            .map(|(path, methods)| {
                let value = methods.into_iter().collect::<Vec<_>>().join(", ");
                // HttpMethod supplies only fixed uppercase ASCII spellings;
                // neither paths nor caller-controlled bytes enter this value.
                let value = HeaderValue::from_str(&value)
                    .expect("fixed catalog methods form a valid Allow header");
                (path, value)
            })
            .collect();
        // Framework OPTIONS and method-not-allowed responses represent a path rather than one
        // exact method. Preserve the strictest cache requirement across every method mounted at
        // that path instead of inheriting whichever descriptor was collected last.
        let private_no_store_paths = self
            .explicit_routes
            .iter()
            .filter(|descriptor| descriptor.requires_private_no_store())
            .map(|descriptor| descriptor.path())
            .collect();
        let cors_paths = self
            .implicit_routes
            .iter()
            .filter_map(|descriptor| {
                (descriptor.kind()
                    == iroha_torii_shared::route_catalog::ImplicitRouteKind::CorsOptions)
                    .then_some(descriptor.path())
            })
            .collect();
        MountedRouteIndex {
            explicit: Arc::new(explicit),
            by_path: Arc::new(by_path),
            allow_by_path: Arc::new(allow_by_path),
            private_no_store_paths: Arc::new(private_no_store_paths),
            cors_paths: Arc::new(cors_paths),
        }
    }
}
/// One router assembly failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RouterAssemblyError {
    /// The canonical descriptor set is itself invalid.
    InvalidCatalog(Vec<CatalogValidationError>),
    /// A group attempted to register a descriptor absent from the catalog.
    UnexpectedRegistration {
        /// Stable ID supplied by the registration.
        stable_route_id: &'static str,
    },
    /// A registration reused a stable ID with different metadata.
    DescriptorMismatch {
        /// Stable ID whose metadata differed.
        stable_route_id: &'static str,
    },
    /// A route disabled by its feature expression was mounted.
    DisabledRegistration {
        /// Stable ID supplied by the registration.
        stable_route_id: &'static str,
    },
    /// A route was registered more than once.
    DuplicateRegistration {
        /// Stable ID supplied by the duplicate registration.
        stable_route_id: &'static str,
    },
    /// A single-method router did not match its descriptor's method.
    MethodMismatch {
        /// Stable ID supplied by the registration.
        stable_route_id: &'static str,
        /// Method declared by the canonical descriptor.
        expected: HttpMethod,
        /// Method carried by the sealed single-method router.
        actual: HttpMethod,
    },
    /// The mounted authentication enforcement or reviewed-handler witness did
    /// not match the catalog.
    AuthenticationMismatch {
        /// Stable ID supplied by the registration.
        stable_route_id: &'static str,
        /// Authentication declared by the canonical descriptor.
        expected: AuthenticationPolicy,
        /// Authentication enforcement or witness carried by the method router.
        actual: AuthenticationPolicy,
    },
    /// One or more enabled catalog routes were never registered.
    MissingRegistrations(Vec<&'static str>),
}
/// Sealed single-method router used by descriptor-level registration.
///
/// Callers cannot construct this type from an arbitrary [`MethodRouter`], so a
/// cataloged registration cannot smuggle additional HTTP methods into Axum.
pub(crate) struct CatalogMethodRouter<S, A = ToriiDefaultAuthentication> {
    method: HttpMethod,
    authentication: A,
    inner: MethodRouter<S>,
}
/// Type state for a route governed only by listener-wide Torii authentication.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ToriiDefaultAuthentication;
/// Type state for a route with no route-specific credential.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct UnauthenticatedRoute;
/// Sealed type state for a route whose special authentication has been fixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SealedAuthentication(AuthenticationPolicy);
/// Authentication type state accepted by catalog registration.
pub(crate) trait MountedAuthentication {
    /// Return the exact catalog policy installed by this state.
    fn policy(&self) -> AuthenticationPolicy;
}
impl MountedAuthentication for ToriiDefaultAuthentication {
    fn policy(&self) -> AuthenticationPolicy {
        AuthenticationPolicy::ToriiDefault
    }
}
impl MountedAuthentication for UnauthenticatedRoute {
    fn policy(&self) -> AuthenticationPolicy {
        AuthenticationPolicy::Unauthenticated
    }
}
impl MountedAuthentication for SealedAuthentication {
    fn policy(&self) -> AuthenticationPolicy {
        self.0
    }
}
mod private {
    /// Private supertrait sealing the set of layerable authentication states.
    pub trait Layerable {}
}
/// Authentication states which may still receive arbitrary middleware.
///
/// Special authentication states deliberately do not implement this trait, so
/// no outer short-circuiting layer can be added after their guard or reviewed
/// handler witness has been fixed.
pub(crate) trait LayerableAuthentication:
    MountedAuthentication + private::Layerable
{
}
impl private::Layerable for ToriiDefaultAuthentication {}
impl private::Layerable for UnauthenticatedRoute {}
impl LayerableAuthentication for ToriiDefaultAuthentication {}
impl LayerableAuthentication for UnauthenticatedRoute {}
/// Authentication witnessed at a reviewed route-handler or protocol boundary.
///
/// This is an explicit review witness, not a proof of the handler's internal
/// behavior; every such handler still requires policy-specific adversarial
/// tests. A handler must authenticate before using protected request data or
/// invoking a protected capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HandlerAuthentication {
    /// An actual owner listener token and immutable private-root scope are verified before export.
    PrivateRootOwnerToken,
    /// Canonical account request authentication performed by the handler.
    ///
    /// These handlers bind the request body and route to an on-ledger account,
    /// enforce freshness and replay protection, and then apply account-scoped
    /// permissions before returning protected data.
    CanonicalAccountSignature,
    /// Optional canonical account authentication performed by the handler.
    ///
    /// Absence of authentication selects the public-dataspace view. Any
    /// supplied canonical authentication material must verify before the
    /// handler may expand visibility.
    OptionalCanonicalAccountSignature,
    /// Canonical signed body authentication performed by the handler.
    ///
    /// The decoded envelope exposes a canonical [`AccountId`](iroha_data_model::account::AccountId)
    /// authority and its signature verifier runs before fee, state, or expensive
    /// execution work. Bounded framing and structural parsing may precede it.
    CanonicalSignedBody,
    /// Manifest-selected content authentication performed by the handler.
    ///
    /// The handler permits anonymous reads only for a ledger-authenticated
    /// `Public` manifest. Protected manifest modes verify the canonical request
    /// and authorize its account against current state before reading content.
    ManifestConditionalContent,
    /// WebAuthn/bootstrap credential exchange performed by the handler.
    OperatorCredentialExchange,
    /// Authentication performed as part of a protocol-native handshake.
    ProtocolHandshake,
    /// A bounded protocol gateway dispatches only through the mounted router,
    /// preserving the exact selected route's sealed authentication boundary.
    NestedRouteAuthentication,
}
impl HandlerAuthentication {
    const fn catalog_policy(self) -> AuthenticationPolicy {
        match self {
            Self::PrivateRootOwnerToken => AuthenticationPolicy::PrivateRootOwnerToken,
            Self::CanonicalAccountSignature => AuthenticationPolicy::CanonicalAccountSignature,
            Self::OptionalCanonicalAccountSignature => {
                AuthenticationPolicy::OptionalCanonicalAccountSignature
            }
            Self::CanonicalSignedBody => AuthenticationPolicy::CanonicalSignedBody,
            Self::ManifestConditionalContent => AuthenticationPolicy::ManifestConditionalContent,
            Self::OperatorCredentialExchange => AuthenticationPolicy::OperatorCredentialExchange,
            Self::ProtocolHandshake => AuthenticationPolicy::ProtocolHandshake,
            Self::NestedRouteAuthentication => AuthenticationPolicy::NestedRouteAuthentication,
        }
    }
}
impl<S, A> CatalogMethodRouter<S, A>
where
    S: Clone + Send + Sync + 'static,
    A: LayerableAuthentication,
{
    /// Apply middleware before any special authentication wrapper is sealed.
    pub(crate) fn layer<L>(self, layer: L) -> Self
    where
        L: Layer<Route> + Clone + Send + Sync + 'static,
        L::Service: Service<Request<Body>, Error = Infallible> + Clone + Send + Sync + 'static,
        <L::Service as Service<Request<Body>>>::Response: IntoResponse + 'static,
        <L::Service as Service<Request<Body>>>::Future: Send + 'static,
    {
        Self {
            method: self.method,
            authentication: self.authentication,
            inner: self.inner.layer(layer),
        }
    }
}
impl<S> CatalogMethodRouter<S, ToriiDefaultAuthentication>
where
    S: Clone + Send + Sync + 'static,
{
    /// Seal the descriptor witness for Torii's route-aware onboarding gate.
    ///
    /// The composed router installs the concrete gate outside media parsing
    /// and inside listener-wide API-token authentication. This marker prevents
    /// either onboarding route from being mounted under the ordinary default
    /// authentication descriptor by accident.
    #[must_use]
    pub(crate) fn authenticated_onboarding(self) -> CatalogMethodRouter<S, SealedAuthentication> {
        CatalogMethodRouter {
            method: self.method,
            authentication: SealedAuthentication(AuthenticationPolicy::OnboardingToken),
            inner: self.inner,
        }
    }
    /// Declare that this route intentionally has no route-specific credential.
    ///
    /// Listener-wide controls, including the configured Torii API token, still
    /// wrap the composed router. The returned state can receive ordinary
    /// middleware but cannot later claim a different authentication policy.
    #[must_use]
    pub(crate) fn unauthenticated(self) -> CatalogMethodRouter<S, UnauthenticatedRoute> {
        CatalogMethodRouter {
            method: self.method,
            authentication: UnauthenticatedRoute,
            inner: self.inner,
        }
    }
    /// Attach a sealed witness for authentication performed inside a handler.
    ///
    /// This call records a reviewed handler boundary; it cannot mechanically
    /// prove the handler's protocol-specific checks or the behavior of layers
    /// already attached to the method router. Reviewers must verify that those
    /// layers cannot return a successful response before the handler runs.
    /// Once called, no general outer middleware can be attached to the returned
    /// router.
    #[must_use]
    pub(crate) fn authenticated_in_handler(
        self,
        authentication: HandlerAuthentication,
    ) -> CatalogMethodRouter<S, SealedAuthentication> {
        CatalogMethodRouter {
            method: self.method,
            authentication: SealedAuthentication(authentication.catalog_policy()),
            inner: self.inner,
        }
    }
}
impl CatalogMethodRouter<SharedAppState, ToriiDefaultAuthentication> {
    /// Install the exact-account SoraCloud command boundary before extraction.
    ///
    /// Every SoraCloud `POST` is mounted through this method. The middleware
    /// authenticates the exact bounded body, applies per-account rate and
    /// in-flight admission, and only then permits the typed handler extractor
    /// to run.
    #[must_use]
    #[cfg(feature = "app_api")]
    pub(crate) fn authenticated_soracloud_command(
        self,
        app_state: SharedAppState,
    ) -> CatalogMethodRouter<SharedAppState, SealedAuthentication> {
        let layer = axum::middleware::from_fn_with_state(
            app_state,
            crate::enforce_soracloud_signed_mutation_request,
        );
        CatalogMethodRouter {
            method: self.method,
            authentication: SealedAuthentication(AuthenticationPolicy::CanonicalAccountSignature),
            inner: self.inner.layer(layer),
        }
    }
    /// Install canonical account authentication over the exact bounded body.
    ///
    /// The middleware buffers at most `max_body_bytes`, verifies the canonical
    /// request signature before the handler can decode or process the body, and
    /// exposes the verified account through request extensions. Body extractors
    /// use the same ceiling unless an explicit inner route layer is narrower.
    #[must_use]
    pub(crate) fn authenticated_canonical_account_body(
        self,
        app_state: SharedAppState,
        max_body_bytes: usize,
    ) -> CatalogMethodRouter<SharedAppState, SealedAuthentication> {
        self.authenticated_canonical_account_body_with_missing_auth(
            app_state,
            max_body_bytes,
            "canonical_authentication_required",
            "canonical account request authentication is required",
        )
    }
    /// Install canonical account authentication with a route-specific missing-auth rejection.
    #[must_use]
    pub(crate) fn authenticated_canonical_account_body_with_missing_auth(
        self,
        app_state: SharedAppState,
        max_body_bytes: usize,
        missing_auth_code: &'static str,
        missing_auth_message: &'static str,
    ) -> CatalogMethodRouter<SharedAppState, SealedAuthentication> {
        let state = crate::CanonicalAccountBodyAuthState {
            app: app_state,
            max_body_bytes,
            missing_auth_code,
            missing_auth_message,
        };
        let layer = axum::middleware::from_fn_with_state(
            state,
            crate::enforce_canonical_account_body_authentication,
        );
        CatalogMethodRouter {
            method: self.method,
            authentication: SealedAuthentication(AuthenticationPolicy::CanonicalAccountSignature),
            // Authentication runs first. Its explicit ceiling also replaces Axum's
            // implicit extractor default; pre-existing route layers remain inside
            // this default so a deliberately narrower extractor limit still wins.
            inner: self
                .inner
                .layer(axum::extract::DefaultBodyLimit::max(max_body_bytes))
                .layer(layer),
        }
    }
    /// Install optional canonical account authentication over the exact bounded body.
    ///
    /// Anonymous requests retain public-dataspace visibility. If any canonical
    /// authentication material is supplied, the middleware verifies it before
    /// body decoding and exposes the resulting visibility through extensions.
    /// The declared ceiling also bounds body extractors, preserving any explicit
    /// narrower limit installed on the route before this authentication layer.
    #[must_use]
    pub(crate) fn optionally_authenticated_canonical_account_body(
        self,
        app_state: SharedAppState,
        max_body_bytes: usize,
    ) -> CatalogMethodRouter<SharedAppState, SealedAuthentication> {
        let state = crate::OptionalCanonicalAccountBodyAuthState {
            app: app_state,
            max_body_bytes,
        };
        let layer = axum::middleware::from_fn_with_state(
            state,
            crate::enforce_optional_canonical_account_body_authentication,
        );
        CatalogMethodRouter {
            method: self.method,
            authentication: SealedAuthentication(
                AuthenticationPolicy::OptionalCanonicalAccountSignature,
            ),
            // Keep anonymous and signed requests on the same declared body bound.
            // An existing inner route limit can still impose a smaller ceiling.
            inner: self
                .inner
                .layer(axum::extract::DefaultBodyLimit::max(max_body_bytes))
                .layer(layer),
        }
    }
    /// Admit, bound, and authenticate an expensive proof body before handler work.
    ///
    /// Physical body admission is outermost, canonical exact-network account
    /// authentication follows over the retained bytes, and only then may a
    /// handler inspect media types or decode the request.
    #[must_use]
    pub(crate) fn authenticated_canonical_account_proof_body(
        self,
        app_state: SharedAppState,
        max_body_bytes: usize,
    ) -> CatalogMethodRouter<SharedAppState, SealedAuthentication> {
        let auth = axum::middleware::from_fn_with_state(
            crate::CanonicalAccountBodyAuthState {
                app: app_state.clone(),
                max_body_bytes,
                missing_auth_code: "canonical_authentication_required",
                missing_auth_message: "canonical account request authentication is required",
            },
            crate::enforce_canonical_account_body_authentication,
        );
        let admission = axum::middleware::from_fn_with_state(
            crate::ProofBodyAdmissionState::new(app_state, max_body_bytes),
            crate::proof_body_admission_middleware,
        );
        CatalogMethodRouter {
            method: self.method,
            authentication: SealedAuthentication(AuthenticationPolicy::CanonicalAccountSignature),
            inner: self
                .inner
                .layer(axum::extract::DefaultBodyLimit::max(max_body_bytes))
                .layer(auth)
                .layer(admission),
        }
    }
    /// Admit a verified-source body before authentication and compilation.
    ///
    /// The outer admission layer owns one complete compiler slot before polling
    /// the body, enforces an absolute body-read deadline, and hands that exact
    /// slot to the blocking compiler worker after canonical authentication.
    #[cfg(feature = "app_api")]
    #[must_use]
    pub(crate) fn authenticated_canonical_account_verified_source_body(
        self,
        app_state: SharedAppState,
        max_body_bytes: usize,
    ) -> CatalogMethodRouter<SharedAppState, SealedAuthentication> {
        let auth = axum::middleware::from_fn_with_state(
            crate::CanonicalAccountBodyAuthState {
                app: app_state.clone(),
                max_body_bytes,
                missing_auth_code: "canonical_authentication_required",
                missing_auth_message: "canonical account request authentication is required",
            },
            crate::enforce_canonical_account_body_authentication,
        );
        let admission = axum::middleware::from_fn_with_state(
            app_state,
            crate::verified_source_body_admission_middleware,
        );
        CatalogMethodRouter {
            method: self.method,
            authentication: SealedAuthentication(AuthenticationPolicy::CanonicalAccountSignature),
            inner: self
                .inner
                .layer(axum::extract::DefaultBodyLimit::max(max_body_bytes))
                .layer(auth)
                .layer(admission),
        }
    }
    /// Apply exact operator authentication and the SoraNet collector guard before body decoding.
    ///
    /// Exact NetworkId-bound operator authentication runs first. The secondary
    /// guard then fails closed unless the source belongs to an allowed network
    /// namespace and consumes a per-operator route budget before the Norito
    /// extractor can inspect attacker-controlled bytes.
    #[must_use]
    pub(crate) fn authenticated_soranet_privacy_collector(
        self,
        app_state: SharedAppState,
        endpoint: &'static str,
    ) -> CatalogMethodRouter<SharedAppState, SealedAuthentication> {
        let state = crate::soranet_privacy_ingress::SoranetPrivacyCollectorAuthState {
            app: app_state.clone(),
            endpoint,
        };
        let collector_layer = axum::middleware::from_fn_with_state(
            state,
            crate::soranet_privacy_ingress::enforce_soranet_privacy_collector_authentication,
        );
        let operator_layer = axum::middleware::from_fn_with_state(
            operator_signatures::BoundedOperatorAccessState {
                app: app_state,
                max_body_bytes:
                    crate::soranet_privacy_ingress::SORANET_PRIVACY_INGEST_MAX_BODY_BYTES,
            },
            operator_signatures::enforce_bounded_operator_access,
        );
        CatalogMethodRouter {
            method: self.method,
            authentication: SealedAuthentication(AuthenticationPolicy::OperatorSignature),
            // Tower applies the most recently added layer first: authenticate
            // and restore the exact body before the collector guard consumes
            // the verified operator extension.
            inner: self.inner.layer(collector_layer).layer(operator_layer),
        }
    }
    /// Apply Torii's request-signature middleware bound to the submitted identity.
    #[must_use]
    pub(crate) fn authenticated_identity_bound(
        self,
        app_state: SharedAppState,
    ) -> CatalogMethodRouter<SharedAppState, SealedAuthentication> {
        let layer = axum::middleware::from_fn_with_state(
            app_state,
            operator_signatures::enforce_identity_bound_signature,
        );
        CatalogMethodRouter {
            method: self.method,
            authentication: SealedAuthentication(AuthenticationPolicy::IdentityBoundSignature),
            inner: self.inner.layer(layer),
        }
    }
    /// Apply the route-specific internal Torii-proxy peer-signature middleware.
    ///
    /// This is cataloged as identity-bound authentication because the cryptographically verified
    /// remote peer is authorized against the routed request by the handler, rather than receiving
    /// generic operator privileges.
    #[must_use]
    pub(crate) fn authenticated_torii_proxy_peer(
        self,
        app_state: SharedAppState,
    ) -> CatalogMethodRouter<SharedAppState, SealedAuthentication> {
        let layer = axum::middleware::from_fn_with_state(
            app_state,
            operator_signatures::enforce_torii_proxy_peer_signature,
        );
        CatalogMethodRouter {
            method: self.method,
            authentication: SealedAuthentication(AuthenticationPolicy::IdentityBoundSignature),
            inner: self.inner.layer(layer),
        }
    }
    /// Apply Torii's mandatory exact-network operator-signature middleware.
    ///
    /// Optional WebAuthn/mTLS operator authentication is enforced as an
    /// additional factor and never replaces the signed method, target, and body.
    ///
    /// Unlike the general [`Self::layer`] method, this method also supplies the
    /// sealed authentication witness checked against the route descriptor.
    #[must_use]
    pub(crate) fn authenticated_operator(
        self,
        app_state: SharedAppState,
    ) -> CatalogMethodRouter<SharedAppState, SealedAuthentication> {
        let layer = axum::middleware::from_fn_with_state(
            app_state,
            operator_signatures::enforce_operator_access,
        );
        CatalogMethodRouter {
            method: self.method,
            authentication: SealedAuthentication(AuthenticationPolicy::OperatorSignature),
            inner: self.inner.layer(layer),
        }
    }
}
macro_rules! catalog_method_constructor {
    ($name:ident, $method:ident, $constructor:ident) => {
        #[doc = concat!("Construct a sealed single-", stringify!($method), " router.")]
        pub(crate) fn $name<H, T, S>(
            handler: H,
        ) -> CatalogMethodRouter<S, ToriiDefaultAuthentication>
        where
            H: Handler<T, S>,
            T: 'static,
            S: Clone + Send + Sync + 'static,
        {
            CatalogMethodRouter {
                method: HttpMethod::$method,
                authentication: ToriiDefaultAuthentication,
                inner: $constructor(handler),
            }
        }
    };
}
/// Construct a sealed GET-only router.
///
/// Axum dispatches HEAD through a GET endpoint even with `MethodFilter::GET`.
/// The completed builder therefore enforces the catalog's exact method set
/// outside the mounted authentication and body layers. Any future HEAD
/// operation must be declared and mounted explicitly.
pub(crate) fn catalog_get<H, T, S>(handler: H) -> CatalogMethodRouter<S, ToriiDefaultAuthentication>
where
    H: Handler<T, S>,
    T: 'static,
    S: Clone + Send + Sync + 'static,
{
    CatalogMethodRouter {
        method: HttpMethod::Get,
        authentication: ToriiDefaultAuthentication,
        inner: on(MethodFilter::GET, handler),
    }
}
catalog_method_constructor!(catalog_post, Post, post);
catalog_method_constructor!(catalog_delete, Delete, delete);
catalog_method_constructor!(catalog_any, Any, any);
/// Reject framework method aliases and misses before route-local middleware.
///
/// The index comes from the completed manifest and the path from Axum's matcher.
/// CORS preflight remains owned by the outer catalog-aware CORS layer; it does
/// not become an explicit application method or inherit GET authentication.
async fn enforce_catalog_method(
    axum::extract::State(index): axum::extract::State<MountedRouteIndex>,
    request: Request<Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let Some(path) = request.extensions().get::<axum::extract::MatchedPath>() else {
        return next.run(request).await;
    };
    let path = path.as_str();
    // Unknown paths remain 404s and ANY-only gateways have no finite Allow
    // set. Every explicit non-ANY path has a value in the completed index.
    let Some(allowed) = index.allow_by_path.get(path) else {
        return next.run(request).await;
    };
    if index
        .explicit
        .contains_key(&(request.method().as_str(), path))
        || index.explicit.contains_key(&("ANY", path))
    {
        return next.run(request).await;
    }
    let allowed = allowed.clone();
    // Supply the exact catalog Allow header before Axum can add its implicit
    // HEAD advertisement. The existing typed method-error response is retained.
    (
        [(axum::http::header::ALLOW, allowed)],
        crate::handler_method_not_allowed().await,
    )
        .into_response()
}
/// Catalog-aware wrapper around an Axum router.
pub(crate) struct RouterBuilder<S = SharedAppState> {
    router: Router<S>,
    app_state: S,
    catalog: RouteCatalog<'static>,
    catalog_by_id: BTreeMap<&'static str, RouteDescriptor>,
    enabled_features: EnabledFeatures<'static>,
    registered_ids: BTreeSet<&'static str>,
    errors: Vec<RouterAssemblyError>,
}
impl<S> RouterBuilder<S>
where
    S: Clone + Send + Sync + 'static,
{
    /// Construct an empty catalog-enforced builder.
    ///
    /// # Errors
    ///
    /// Returns [`RouterAssemblyError::InvalidCatalog`] if the supplied
    /// descriptor set is not internally valid.
    pub(crate) fn new(
        app_state: S,
        catalog: RouteCatalog<'static>,
        enabled_features: EnabledFeatures<'static>,
    ) -> Result<Self, RouterAssemblyError> {
        catalog
            .validate()
            .map_err(RouterAssemblyError::InvalidCatalog)?;
        let catalog_by_id = catalog
            .routes()
            .iter()
            .map(|descriptor| (descriptor.stable_route_id(), *descriptor))
            .collect();
        Ok(Self {
            router: Router::new().without_v07_checks(),
            app_state,
            catalog,
            catalog_by_id,
            enabled_features,
            registered_ids: BTreeSet::new(),
            errors: Vec::new(),
        })
    }
    /// Mount one route at the descriptor's exact path.
    ///
    /// Prefer this method for ordinary HTTP operations. The descriptor, rather
    /// than a second path string, is the mount source of truth.
    pub(crate) fn route<A>(
        &mut self,
        descriptor: &'static RouteDescriptor,
        method_router: CatalogMethodRouter<S, A>,
    ) where
        A: MountedAuthentication,
    {
        if descriptor.method() != method_router.method {
            self.errors.push(RouterAssemblyError::MethodMismatch {
                stable_route_id: descriptor.stable_route_id(),
                expected: descriptor.method(),
                actual: method_router.method,
            });
            return;
        }
        let actual_authentication = method_router.authentication.policy();
        if descriptor.authentication() != actual_authentication {
            self.errors
                .push(RouterAssemblyError::AuthenticationMismatch {
                    stable_route_id: descriptor.stable_route_id(),
                    expected: descriptor.authentication(),
                    actual: actual_authentication,
                });
            return;
        }
        if !self.register_route(descriptor) {
            return;
        }
        self.router =
            std::mem::take(&mut self.router).route(descriptor.path(), method_router.inner);
    }
    /// Get the shared state held by the builder.
    #[must_use]
    pub(crate) fn state(&self) -> &S {
        &self.app_state
    }
    /// Finish composition only if every route family is fully cataloged.
    ///
    /// # Errors
    ///
    /// Returns all registration and completeness failures.
    pub(crate) fn finish(
        self,
    ) -> Result<(Router<S>, MountedRouteManifest), Vec<RouterAssemblyError>> {
        self.finish_inner()
    }
    fn register_route(&mut self, descriptor: &'static RouteDescriptor) -> bool {
        let stable_route_id = descriptor.stable_route_id();
        let Some(expected) = self.catalog_by_id.get(stable_route_id) else {
            self.errors
                .push(RouterAssemblyError::UnexpectedRegistration { stable_route_id });
            return false;
        };
        if expected != descriptor {
            self.errors
                .push(RouterAssemblyError::DescriptorMismatch { stable_route_id });
            return false;
        }
        if !descriptor.feature_gate().is_enabled(self.enabled_features) {
            self.errors
                .push(RouterAssemblyError::DisabledRegistration { stable_route_id });
            return false;
        }
        if !self.registered_ids.insert(stable_route_id) {
            self.errors
                .push(RouterAssemblyError::DuplicateRegistration { stable_route_id });
            return false;
        }
        true
    }
    fn finish_inner(self) -> Result<(Router<S>, MountedRouteManifest), Vec<RouterAssemblyError>> {
        let enabled = self
            .catalog
            .project(CatalogProjection::Mounted, self.enabled_features);
        let missing: Vec<_> = enabled
            .iter()
            .filter_map(|route| {
                (!self.registered_ids.contains(route.stable_route_id()))
                    .then_some(route.stable_route_id())
            })
            .collect();
        let mut errors = self.errors;
        if !missing.is_empty() {
            errors.push(RouterAssemblyError::MissingRegistrations(missing));
        }
        if !errors.is_empty() {
            return Err(errors);
        }
        let explicit_routes: Vec<_> = enabled.into_iter().copied().collect();
        let implicit_routes =
            RouteCatalog::new(&explicit_routes).implicit_routes(self.enabled_features);
        let manifest = MountedRouteManifest {
            explicit_routes,
            implicit_routes,
        };
        // Install the fallback before the guard: replacing it after layering
        // would discard enforcement for Axum's method-miss branch.
        let router = self
            .router
            .method_not_allowed_fallback(crate::handler_method_not_allowed)
            .layer(axum::middleware::from_fn_with_state(
                manifest.route_index(),
                enforce_catalog_method,
            ));
        Ok((router, manifest))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode},
    };
    use iroha_torii_shared::route_catalog::{
        ApiSurface, FeatureGate, ImplicitRouteKind, Listener, RouteProjections,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt as _;
    const READ: RouteDescriptor = RouteDescriptor::new(
        "test.read",
        HttpMethod::Get,
        "/v1/tests/resource",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_cors_options(true);
    const WRITE: RouteDescriptor = RouteDescriptor::new(
        "test.write",
        HttpMethod::Post,
        "/v1/tests/resource",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_cors_options(true);
    const FEATURED: RouteDescriptor = RouteDescriptor::new(
        "test.featured",
        HttpMethod::Get,
        "/v1/tests/featured",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_feature_gate(FeatureGate::Feature("test_feature"));
    const HANDSHAKE: RouteDescriptor = RouteDescriptor::new(
        "test.handshake",
        HttpMethod::Get,
        "/v1/tests/handshake",
        ApiSurface::Protocol,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_authentication(AuthenticationPolicy::ProtocolHandshake);
    const PUBLIC_HEALTH: RouteDescriptor = RouteDescriptor::new(
        "test.health",
        HttpMethod::Get,
        "/health",
        ApiSurface::Protocol,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_authentication(AuthenticationPolicy::Unauthenticated)
    .with_path_policy(
        iroha_torii_shared::route_catalog::PathPolicy::ProtocolException {
            reason: "test health endpoint",
        },
    );
    const OPERATOR: RouteDescriptor = RouteDescriptor::new(
        "test.operator",
        HttpMethod::Get,
        "/v1/tests/operator",
        ApiSurface::Operator,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Operator,
    )
    .with_authentication(AuthenticationPolicy::OperatorSignature);
    const TORII_PROXY_PEER_AUTHENTICATED: RouteDescriptor = RouteDescriptor::new(
        "test.torii_proxy_peer_authenticated",
        HttpMethod::Post,
        "/v1/tests/torii-proxy-peer-authenticated",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::Mutation,
        AdmissionPolicy::ValidatorRosterMember,
    )
    .with_authentication(AuthenticationPolicy::IdentityBoundSignature);
    const ACCOUNT_AUTHENTICATED: RouteDescriptor = RouteDescriptor::new(
        "test.account_authenticated",
        HttpMethod::Post,
        "/v1/tests/account-authenticated",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::Mutation,
        AdmissionPolicy::AuthenticatedAccount,
    )
    .with_authentication(AuthenticationPolicy::CanonicalAccountSignature);
    const OPTIONAL_DATASPACE_AUTHENTICATED: RouteDescriptor = RouteDescriptor::new(
        "test.optional_dataspace_authenticated",
        HttpMethod::Post,
        "/v1/tests/optional-dataspace-authenticated",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ExpensiveCompute,
        AdmissionPolicy::DataspaceVisible,
    )
    .with_authentication(AuthenticationPolicy::OptionalCanonicalAccountSignature);
    const SIGNED_BODY_AUTHENTICATED: RouteDescriptor = RouteDescriptor::new(
        "test.signed_body_authenticated",
        HttpMethod::Post,
        "/v1/tests/signed-body-authenticated",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::Mutation,
        AdmissionPolicy::AuthenticatedAccount,
    )
    .with_authentication(AuthenticationPolicy::CanonicalSignedBody);
    const MANIFEST_CONDITIONAL_CONTENT: RouteDescriptor = RouteDescriptor::new(
        "test.manifest_conditional_content",
        HttpMethod::Get,
        "/v1/tests/manifest-conditional-content",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_authentication(AuthenticationPolicy::ManifestConditionalContent);
    const ROUTES: &[RouteDescriptor] = &[READ, WRITE, FEATURED];
    #[test]
    fn kagemusha_catalog_contains_only_enrollment_and_authenticated_load_originals() {
        let catalog = RouteCatalog::new(iroha_torii_shared::route_catalog::CATALOGED_ROUTES);
        let load_read = iroha_torii_shared::route_catalog::contracts_and_verification_keys::KAGEMUSHA_LOAD_ISSUANCE_GET;
        let finality_read = iroha_torii_shared::route_catalog::contracts_and_verification_keys::KAGEMUSHA_LOAD_FINALITY_GET;
        let epoch_read = iroha_torii_shared::route_catalog::contracts_and_verification_keys::KAGEMUSHA_LOAD_EPOCH_GET;
        let enrollment = iroha_torii_shared::route_catalog::contracts_and_verification_keys::KAGEMUSHA_ENROLLMENT_POST;
        assert_eq!(finality_read.method(), HttpMethod::Get);
        assert_eq!(finality_read.effect(), RouteEffect::ReadOnly);
        assert_eq!(epoch_read.method(), HttpMethod::Get);
        assert_eq!(epoch_read.effect(), RouteEffect::ReadOnly);
        assert_eq!(
            epoch_read.authentication(),
            AuthenticationPolicy::CanonicalAccountSignature
        );
        assert_eq!(
            finality_read.authentication(),
            AuthenticationPolicy::CanonicalAccountSignature
        );
        assert_eq!(load_read.method(), HttpMethod::Get);
        assert_eq!(load_read.effect(), RouteEffect::ReadOnly);
        assert_eq!(
            load_read.authentication(),
            AuthenticationPolicy::CanonicalAccountSignature
        );
        for projection in [
            CatalogProjection::Mounted,
            CatalogProjection::OpenApi,
            CatalogProjection::Sdk,
            CatalogProjection::Mcp,
        ] {
            for features in [EnabledFeatures::none(), EnabledFeatures::new(&["app_api"])] {
                assert!(
                    catalog
                        .project(projection, features)
                        .iter()
                        .all(|route| !route.path().starts_with("/v1/kagemusha/")
                            || **route == load_read
                            || **route == finality_read
                            || **route == epoch_read
                            || **route == enrollment),
                    "retired KAGEMUSHA transport remains in {projection:?}"
                );
            }
        }
    }
    #[tokio::test]
    async fn ledger_original_carriers_mount_without_optional_features() {
        use iroha_torii_shared::route_catalog::core;
        const LEDGER_CARRIERS: &[RouteDescriptor] =
            &[core::RESOURCE_NAMES_STATE, core::AUTHORITY_ORIGINALS];
        let mut builder = RouterBuilder::new(
            (),
            RouteCatalog::new(LEDGER_CARRIERS),
            EnabledFeatures::none(),
        )
        .expect("ledger original-carrier catalog is valid");
        builder.route(
            &core::RESOURCE_NAMES_STATE,
            catalog_get(|| async { StatusCode::NO_CONTENT })
                .authenticated_in_handler(HandlerAuthentication::CanonicalAccountSignature),
        );
        builder.route(
            &core::AUTHORITY_ORIGINALS,
            catalog_post(|| async { StatusCode::NO_CONTENT })
                .authenticated_in_handler(HandlerAuthentication::CanonicalAccountSignature),
        );
        let (router, manifest) = builder
            .finish()
            .expect("every build requires and accepts both ledger original carriers");
        assert_eq!(manifest.explicit_routes(), LEDGER_CARRIERS);
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(
                        core::RESOURCE_NAMES_STATE
                            .path()
                            .replace("{challenge}", &"ab".repeat(32)),
                    )
                    .body(Body::empty())
                    .expect("resource-names request"),
            )
            .await
            .expect("resource-names route response");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(core::AUTHORITY_ORIGINALS.path())
                    .body(Body::empty())
                    .expect("authority-originals request"),
            )
            .await
            .expect("authority-originals route response");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        for projection in [CatalogProjection::OpenApi, CatalogProjection::Sdk] {
            assert_eq!(
                RouteCatalog::new(LEDGER_CARRIERS)
                    .project(projection, EnabledFeatures::none())
                    .len(),
                LEDGER_CARRIERS.len()
            );
        }
        assert!(
            RouteCatalog::new(LEDGER_CARRIERS)
                .project(CatalogProjection::Mcp, EnabledFeatures::none())
                .is_empty()
        );
    }
    #[cfg(feature = "app_api")]
    async fn short_circuit_success(
        _request: Request<Body>,
        _next: axum::middleware::Next,
    ) -> StatusCode {
        StatusCode::IM_A_TEAPOT
    }
    #[tokio::test]
    async fn complete_manifest_matches_registered_routes_and_keeps_get_exact() {
        let mut builder =
            RouterBuilder::new((), RouteCatalog::new(ROUTES), EnabledFeatures::none())
                .expect("valid catalog");
        assert_eq!(builder.catalog_by_id.len(), ROUTES.len());
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let handler_calls = std::sync::Arc::clone(&calls);
        builder.route(
            &READ,
            catalog_get(move || {
                let handler_calls = std::sync::Arc::clone(&handler_calls);
                async move {
                    handler_calls.fetch_add(1, Ordering::SeqCst);
                    "read"
                }
            }),
        );
        builder.route(&WRITE, catalog_post(|| async { StatusCode::NO_CONTENT }));
        let (router, manifest) = builder.finish().expect("complete registration");
        assert_eq!(manifest.explicit_routes(), &[READ, WRITE]);
        assert_eq!(manifest.implicit_routes().len(), 1);
        assert!(manifest.implicit_routes().iter().any(|route| {
            route.kind() == ImplicitRouteKind::CorsOptions && route.path() == READ.path()
        }));
        let matched = manifest
            .route_index()
            .resolve(&Method::GET, Some(READ.path()));
        assert_eq!(matched.effect(), Some(RouteEffect::ReadOnly));
        assert_eq!(matched.admission(), Some(AdmissionPolicy::Public));
        assert_eq!(matched.transport(), Some(RouteTransport::Http));
        let head = manifest
            .route_index()
            .resolve(&Method::HEAD, Some(READ.path()));
        assert_eq!(head.stable_route_id(), "http.method_not_allowed");
        assert_eq!(head.transport(), None);
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::HEAD)
                    .uri(READ.path())
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(response.headers()[axum::http::header::ALLOW], "GET, POST");
        for method in [Method::DELETE, Method::PUT, Method::OPTIONS, Method::TRACE] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(READ.path())
                        .body(Body::from("not an admitted operation"))
                        .expect("unsupported method request"),
                )
                .await
                .expect("method fallback response");
            assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
            assert_eq!(response.headers()[axum::http::header::ALLOW], "GET, POST");
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
        for (method, status) in [
            (Method::GET, StatusCode::OK),
            (Method::POST, StatusCode::NO_CONTENT),
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(READ.path())
                        .body(Body::empty())
                        .expect("declared method request"),
                )
                .await
                .expect("declared method response");
            assert_eq!(response.status(), status);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let missing = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::HEAD)
                    .uri("/v1/tests/absent")
                    .body(Body::empty())
                    .expect("unknown path request"),
            )
            .await
            .expect("unknown path response");
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        assert!(!missing.headers().contains_key(axum::http::header::ALLOW));
        let cors = router.layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods([Method::GET, Method::POST]),
        );
        let preflight = cors
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri(READ.path())
                    .header(axum::http::header::ORIGIN, "https://client.example")
                    .header(axum::http::header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
                    .body(Body::empty())
                    .expect("declared CORS preflight"),
            )
            .await
            .expect("CORS response");
        assert_eq!(preflight.status(), StatusCode::OK);
        assert_eq!(
            preflight.headers()[axum::http::header::ACCESS_CONTROL_ALLOW_METHODS],
            "GET,POST"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            manifest
                .route_index()
                .resolve(&Method::OPTIONS, Some(READ.path()))
                .stable_route_id(),
            "http.cors_preflight"
        );

        const GATEWAY: RouteDescriptor = RouteDescriptor::new(
            "test.any_gateway",
            HttpMethod::Any,
            "/v1/tests/gateway",
            ApiSurface::Protocol,
            Listener::Torii,
            RouteEffect::ReadOnly,
            AdmissionPolicy::Public,
        );
        let mut gateway =
            RouterBuilder::new((), RouteCatalog::new(&[GATEWAY]), EnabledFeatures::none())
                .expect("valid protocol gateway catalog");
        let gateway_calls = std::sync::Arc::new(AtomicUsize::new(0));
        let handler_calls = std::sync::Arc::clone(&gateway_calls);
        gateway.route(
            &GATEWAY,
            catalog_any(move || {
                let calls = std::sync::Arc::clone(&handler_calls);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    StatusCode::NO_CONTENT
                }
            }),
        );
        let (gateway, gateway_manifest) = gateway.finish().expect("exact ANY registration");
        assert_eq!(gateway_manifest.explicit_routes(), &[GATEWAY]);
        for method in [Method::HEAD, Method::GET, Method::POST, Method::OPTIONS] {
            let response = gateway
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(GATEWAY.path())
                        .body(Body::empty())
                        .expect("gateway request"),
                )
                .await
                .expect("gateway response");
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            assert!(!response.headers().contains_key(axum::http::header::ALLOW));
        }
        assert_eq!(gateway_calls.load(Ordering::SeqCst), 4);
    }
    #[test]
    fn unsafe_effect_and_admission_metadata_cannot_reach_mounting() {
        const UNSAFE: RouteDescriptor = RouteDescriptor::new(
            "test.unsafe_public_mutation",
            HttpMethod::Post,
            "/v1/tests/unsafe-public-mutation",
            ApiSurface::Public,
            Listener::Torii,
            RouteEffect::Mutation,
            AdmissionPolicy::Public,
        );
        let Err(error) =
            RouterBuilder::new((), RouteCatalog::new(&[UNSAFE]), EnabledFeatures::none())
        else {
            panic!("unsafe catalog metadata must fail before route mounting");
        };
        assert!(matches!(error, RouterAssemblyError::InvalidCatalog(_)));
    }
    #[test]
    fn duplicate_registration_is_rejected_without_mounting_twice() {
        let mut builder =
            RouterBuilder::new((), RouteCatalog::new(&[READ]), EnabledFeatures::none())
                .expect("valid catalog");
        builder.route(&READ, catalog_get(|| async {}));
        builder.route(&READ, catalog_get(|| async {}));
        assert_eq!(builder.registered_ids.len(), 1);
        let errors = builder.finish().expect_err("duplicate must fail");
        assert!(errors.iter().any(|error| {
            matches!(
                error,
                RouterAssemblyError::DuplicateRegistration {
                    stable_route_id: "test.read"
                }
            )
        }));
    }
    #[test]
    fn missing_and_disabled_registrations_are_distinct() {
        let builder = RouterBuilder::new((), RouteCatalog::new(&[READ]), EnabledFeatures::none())
            .expect("valid catalog");
        let errors = builder.finish().expect_err("missing route must fail");
        assert_eq!(
            errors,
            vec![RouterAssemblyError::MissingRegistrations(vec!["test.read"])]
        );
        let mut builder =
            RouterBuilder::new((), RouteCatalog::new(&[FEATURED]), EnabledFeatures::none())
                .expect("valid catalog");
        builder.route(&FEATURED, catalog_get(|| async {}));
        let errors = builder.finish().expect_err("disabled route must fail");
        assert_eq!(
            errors,
            vec![RouterAssemblyError::DisabledRegistration {
                stable_route_id: "test.featured"
            }]
        );
    }
    #[test]
    fn descriptor_mismatch_and_unexpected_route_are_rejected() {
        const MISMATCH: RouteDescriptor = RouteDescriptor::new(
            "test.read",
            HttpMethod::Get,
            "/v1/tests/different",
            ApiSurface::Public,
            Listener::Torii,
            RouteEffect::ReadOnly,
            AdmissionPolicy::Public,
        );
        const UNEXPECTED: RouteDescriptor = RouteDescriptor::new(
            "test.unexpected",
            HttpMethod::Get,
            "/v1/tests/unexpected",
            ApiSurface::Public,
            Listener::Torii,
            RouteEffect::ReadOnly,
            AdmissionPolicy::Public,
        );
        let mut builder =
            RouterBuilder::new((), RouteCatalog::new(&[READ]), EnabledFeatures::none())
                .expect("valid catalog");
        builder.route(&MISMATCH, catalog_get(|| async {}));
        builder.route(&UNEXPECTED, catalog_get(|| async {}));
        let errors = builder
            .finish()
            .expect_err("invalid registrations must fail");
        assert!(errors.iter().any(|error| {
            matches!(
                error,
                RouterAssemblyError::DescriptorMismatch {
                    stable_route_id: "test.read"
                }
            )
        }));
        assert!(errors.iter().any(|error| {
            matches!(
                error,
                RouterAssemblyError::UnexpectedRegistration {
                    stable_route_id: "test.unexpected"
                }
            )
        }));
    }
    #[test]
    fn descriptor_method_mismatch_fails_before_mounting() {
        let mut builder =
            RouterBuilder::new((), RouteCatalog::new(&[READ]), EnabledFeatures::none())
                .expect("valid catalog");
        builder.route(&READ, catalog_post(|| async {}));
        let errors = builder.finish().expect_err("method mismatch must fail");
        assert!(errors.iter().any(|error| {
            matches!(
                error,
                RouterAssemblyError::MethodMismatch {
                    stable_route_id: "test.read",
                    expected: HttpMethod::Get,
                    actual: HttpMethod::Post,
                }
            )
        }));
    }
    #[test]
    fn authentication_policy_mismatch_fails_before_mounting() {
        let mut builder =
            RouterBuilder::new((), RouteCatalog::new(&[HANDSHAKE]), EnabledFeatures::none())
                .expect("valid catalog");
        builder.route(&HANDSHAKE, catalog_get(|| async {}));
        let errors = builder
            .finish()
            .expect_err("missing handler authentication witness must fail");
        assert!(errors.iter().any(|error| matches!(
            error,
            RouterAssemblyError::AuthenticationMismatch {
                stable_route_id: "test.handshake",
                expected: AuthenticationPolicy::ProtocolHandshake,
                actual: AuthenticationPolicy::ToriiDefault,
            }
        )));
    }
    #[test]
    fn arbitrary_middleware_cannot_claim_operator_authentication() {
        let mut builder =
            RouterBuilder::new((), RouteCatalog::new(&[OPERATOR]), EnabledFeatures::none())
                .expect("valid catalog");
        builder.route(
            &OPERATOR,
            catalog_get(|| async {}).layer(axum::Extension(())),
        );
        let errors = builder
            .finish()
            .expect_err("an arbitrary layer must not satisfy operator authentication");
        assert!(errors.iter().any(|error| matches!(
            error,
            RouterAssemblyError::AuthenticationMismatch {
                stable_route_id: "test.operator",
                expected: AuthenticationPolicy::OperatorSignature,
                actual: AuthenticationPolicy::ToriiDefault,
            }
        )));
    }
    #[cfg(feature = "app_api")]
    #[test]
    fn torii_proxy_peer_witness_is_sealed_as_identity_bound_authentication() {
        let app = crate::mk_app_state_for_tests();
        let mut builder = RouterBuilder::new(
            app.clone(),
            RouteCatalog::new(&[TORII_PROXY_PEER_AUTHENTICATED]),
            EnabledFeatures::none(),
        )
        .expect("valid catalog");
        builder.route(
            &TORII_PROXY_PEER_AUTHENTICATED,
            catalog_post(|| async { StatusCode::NO_CONTENT })
                .authenticated_torii_proxy_peer(app.clone()),
        );
        let (_, manifest) = builder
            .finish()
            .expect("Torii proxy peer authentication witness must match the catalog");
        assert_eq!(
            manifest.explicit_routes(),
            &[TORII_PROXY_PEER_AUTHENTICATED]
        );
    }
    #[test]
    fn handler_and_unauthenticated_witnesses_match_only_their_declared_policy() {
        let mut builder = RouterBuilder::new(
            (),
            RouteCatalog::new(&[HANDSHAKE, PUBLIC_HEALTH]),
            EnabledFeatures::none(),
        )
        .expect("valid catalog");
        builder.route(
            &HANDSHAKE,
            catalog_get(|| async {})
                .authenticated_in_handler(HandlerAuthentication::ProtocolHandshake),
        );
        builder.route(&PUBLIC_HEALTH, catalog_get(|| async {}).unauthenticated());
        let (_, manifest) = builder.finish().expect("matching witnesses must mount");
        assert_eq!(manifest.explicit_routes(), &[HANDSHAKE, PUBLIC_HEALTH]);
    }
    #[test]
    fn canonical_account_handler_witness_matches_only_account_authentication() {
        let mut builder = RouterBuilder::new(
            (),
            RouteCatalog::new(&[ACCOUNT_AUTHENTICATED]),
            EnabledFeatures::none(),
        )
        .expect("valid catalog");
        builder.route(
            &ACCOUNT_AUTHENTICATED,
            catalog_post(|| async {})
                .authenticated_in_handler(HandlerAuthentication::CanonicalAccountSignature),
        );
        let (_, manifest) = builder
            .finish()
            .expect("canonical account witness must mount");
        assert_eq!(manifest.explicit_routes(), &[ACCOUNT_AUTHENTICATED]);
    }
    #[cfg(feature = "app_api")]
    #[tokio::test]
    async fn soracloud_command_witness_authenticates_before_the_handler() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let app = crate::mk_app_state_for_tests();
        let calls = Arc::new(AtomicUsize::new(0));
        let handler_calls = Arc::clone(&calls);
        let mut builder = RouterBuilder::new(
            app.clone(),
            RouteCatalog::new(&[ACCOUNT_AUTHENTICATED]),
            EnabledFeatures::none(),
        )
        .expect("valid SoraCloud command catalog");
        builder.route(
            &ACCOUNT_AUTHENTICATED,
            catalog_post(move || {
                let handler_calls = Arc::clone(&handler_calls);
                async move {
                    handler_calls.fetch_add(1, Ordering::SeqCst);
                    StatusCode::NO_CONTENT
                }
            })
            .authenticated_soracloud_command(app.clone()),
        );
        let (router, _) = builder
            .finish()
            .expect("sealed SoraCloud authentication must match the catalog");
        let response = router
            .with_state(app)
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(ACCOUNT_AUTHENTICATED.path())
                    .body(Body::from(br#"{"operation":"unsigned"}"#.to_vec()))
                    .expect("unsigned SoraCloud request"),
            )
            .await
            .expect("unsigned SoraCloud response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    #[cfg(feature = "app_api")]
    #[tokio::test]
    async fn canonical_body_route_uses_declared_extractor_limit_and_preserves_narrower_limits() {
        use crate::utils::extractors::NoritoJson;
        use axum::{Extension, extract::DefaultBodyLimit};
        use std::sync::Arc;

        let _guard = crate::tests_runtime_handlers::app_auth_test_guard(
            crate::app_auth::CanonicalRequestAuthConfig::default(),
        );
        let key_pair = crate::tests_runtime_handlers::checked_torii_test_ed25519_keypair(
            0x71,
            "derive canonical body-bound route test key",
        );
        let account = iroha_data_model::account::AccountId::new(key_pair.public_key().clone());
        let app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world(
            crate::tests_runtime_handlers::world_with_account(&account),
        );
        const LIMIT: usize = 3 * 1024 * 1024;
        for (body_bytes, inner_limit, expected_status) in [
            (LIMIT - 1, None, StatusCode::NO_CONTENT),
            (LIMIT, None, StatusCode::NO_CONTENT),
            (LIMIT + 1, None, StatusCode::PAYLOAD_TOO_LARGE),
            (1024, Some(1024), StatusCode::NO_CONTENT),
            (1025, Some(1024), StatusCode::PAYLOAD_TOO_LARGE),
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let handler_calls = Arc::clone(&calls);
            let expected_account = account.clone();
            let mut method = catalog_post(
                move |Extension(verified): Extension<crate::app_auth::VerifiedCanonicalRequest>,
                      NoritoJson(body): NoritoJson<String>| {
                    let calls = Arc::clone(&handler_calls);
                    let expected_account = expected_account.clone();
                    async move {
                        assert_eq!(verified.account, expected_account);
                        assert_eq!(body.len(), body_bytes - 2);
                        calls.fetch_add(1, Ordering::SeqCst);
                        StatusCode::NO_CONTENT
                    }
                },
            );
            if let Some(inner_limit) = inner_limit {
                method = method.layer(DefaultBodyLimit::max(inner_limit));
            }
            let mut builder = RouterBuilder::new(
                app.clone(),
                RouteCatalog::new(&[ACCOUNT_AUTHENTICATED]),
                EnabledFeatures::none(),
            )
            .expect("valid bounded account catalog");
            builder.route(
                &ACCOUNT_AUTHENTICATED,
                method.authenticated_canonical_account_body(app.clone(), LIMIT),
            );
            let (router, _) = builder.finish().expect("sealed account body route");
            let router = router.with_state(app.clone());
            let uri: axum::http::Uri = ACCOUNT_AUTHENTICATED.path().parse().expect("route URI");
            let mut body = vec![b'x'; body_bytes];
            body[0] = b'"';
            body[body_bytes - 1] = b'"';
            let headers = crate::tests_runtime_handlers::signed_app_headers(
                &account,
                &key_pair,
                &Method::POST,
                &uri,
                &body,
            );
            let mut request = Request::builder()
                .method(Method::POST)
                .uri(uri)
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .expect("signed bounded JSON request");
            request.headers_mut().extend(headers);
            let response = router
                .oneshot(request)
                .await
                .expect("bounded route response");
            assert_eq!(
                response.status(),
                expected_status,
                "body bytes {body_bytes}"
            );
            assert_eq!(
                calls.load(Ordering::SeqCst),
                usize::from(expected_status.is_success())
            );
        }
    }

    #[cfg(feature = "app_api")]
    #[tokio::test]
    async fn canonical_body_route_authenticates_large_bodies_before_typed_decode() {
        use crate::utils::extractors::NoritoJson;
        use axum::Extension;
        use std::sync::Arc;

        let _guard = crate::tests_runtime_handlers::app_auth_test_guard(
            crate::app_auth::CanonicalRequestAuthConfig::default(),
        );
        let key_pair = crate::tests_runtime_handlers::checked_torii_test_ed25519_keypair(
            0x72,
            "derive canonical large-body authentication test key",
        );
        let account = iroha_data_model::account::AccountId::new(key_pair.public_key().clone());
        let app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world(
            crate::tests_runtime_handlers::world_with_account(&account),
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let handler_calls = Arc::clone(&calls);
        let mut builder = RouterBuilder::new(
            app.clone(),
            RouteCatalog::new(&[ACCOUNT_AUTHENTICATED]),
            EnabledFeatures::none(),
        )
        .expect("valid authenticated body catalog");
        builder.route(
            &ACCOUNT_AUTHENTICATED,
            catalog_post(
                move |Extension(_verified): Extension<
                    crate::app_auth::VerifiedCanonicalRequest,
                >,
                      NoritoJson(_body): NoritoJson<String>| {
                    let calls = Arc::clone(&handler_calls);
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        StatusCode::NO_CONTENT
                    }
                },
            )
            .authenticated_canonical_account_body(app.clone(), 3 * 1024 * 1024),
        );
        let (router, _) = builder.finish().expect("sealed authenticated body route");
        let router = router.with_state(app);
        let uri: axum::http::Uri = ACCOUNT_AUTHENTICATED.path().parse().expect("route URI");
        let body = vec![b'{'; 2 * 1024 * 1024 + 1];
        let unsigned = Request::builder()
            .method(Method::POST)
            .uri(uri.clone())
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.clone()))
            .expect("unsigned malformed large body");
        assert_eq!(
            router
                .clone()
                .oneshot(unsigned)
                .await
                .expect("unsigned response")
                .status(),
            StatusCode::UNAUTHORIZED,
        );
        let mut tampered = body.clone();
        tampered[0] = b'[';
        let headers = crate::tests_runtime_handlers::signed_app_headers(
            &account,
            &key_pair,
            &Method::POST,
            &uri,
            &body,
        );
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(tampered))
            .expect("tampered malformed large body");
        request.headers_mut().extend(headers);
        assert_eq!(
            router
                .oneshot(request)
                .await
                .expect("tampered response")
                .status(),
            StatusCode::FORBIDDEN,
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[cfg(feature = "app_api")]
    #[tokio::test]
    async fn optional_canonical_body_route_keeps_exact_bounds_and_authentication() {
        use crate::utils::extractors::NoritoJson;
        use axum::Extension;
        use std::sync::Arc;

        let _guard = crate::tests_runtime_handlers::app_auth_test_guard(
            crate::app_auth::CanonicalRequestAuthConfig::default(),
        );
        let key_pair = crate::tests_runtime_handlers::checked_torii_test_ed25519_keypair(
            0x73,
            "derive optional body-bound authentication test key",
        );
        let account = iroha_data_model::account::AccountId::new(key_pair.public_key().clone());
        let app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world(
            crate::tests_runtime_handlers::world_with_account(&account),
        );
        const LIMIT: usize = 3 * 1024 * 1024;
        let calls = Arc::new(AtomicUsize::new(0));
        let signed_calls = Arc::new(AtomicUsize::new(0));
        let handler_calls = Arc::clone(&calls);
        let handler_signed_calls = Arc::clone(&signed_calls);
        let expected_account = account.clone();
        let mut builder = RouterBuilder::new(
            app.clone(),
            RouteCatalog::new(&[OPTIONAL_DATASPACE_AUTHENTICATED]),
            EnabledFeatures::none(),
        )
        .expect("valid optional authenticated body catalog");
        builder.route(
            &OPTIONAL_DATASPACE_AUTHENTICATED,
            catalog_post(
                move |Extension(visibility): Extension<crate::ToriiAccountReadVisibility>,
                      NoritoJson(body): NoritoJson<String>| {
                    let calls = Arc::clone(&handler_calls);
                    let signed_calls = Arc::clone(&handler_signed_calls);
                    let expected_account = expected_account.clone();
                    async move {
                        assert_eq!(body.len(), LIMIT - 2);
                        if visibility.is_signed() {
                            assert_eq!(visibility.caller(), Some(&expected_account));
                            signed_calls.fetch_add(1, Ordering::SeqCst);
                        } else {
                            assert!(visibility.caller().is_none());
                        }
                        calls.fetch_add(1, Ordering::SeqCst);
                        StatusCode::NO_CONTENT
                    }
                },
            )
            .optionally_authenticated_canonical_account_body(app.clone(), LIMIT),
        );
        let (router, _) = builder.finish().expect("sealed optional body route");
        let router = router.with_state(app);
        let uri: axum::http::Uri = OPTIONAL_DATASPACE_AUTHENTICATED
            .path()
            .parse()
            .expect("route URI");
        for signed in [false, true] {
            for (body_bytes, expected_status) in [
                (LIMIT, StatusCode::NO_CONTENT),
                (LIMIT + 1, StatusCode::PAYLOAD_TOO_LARGE),
            ] {
                let mut body = vec![b'x'; body_bytes];
                body[0] = b'"';
                body[body_bytes - 1] = b'"';
                let headers = signed.then(|| {
                    crate::tests_runtime_handlers::signed_app_headers(
                        &account,
                        &key_pair,
                        &Method::POST,
                        &uri,
                        &body,
                    )
                });
                let mut request = Request::builder()
                    .method(Method::POST)
                    .uri(uri.clone())
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .expect("optional authenticated body request");
                if let Some(headers) = headers {
                    request.headers_mut().extend(headers);
                }
                let response = router
                    .clone()
                    .oneshot(request)
                    .await
                    .expect("optional response");
                assert_eq!(response.status(), expected_status);
            }
        }
        let partial = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .header(crate::HEADER_ACCOUNT, account.to_string())
            .body(Body::from("{"))
            .expect("partial authentication request");
        assert_eq!(
            router
                .oneshot(partial)
                .await
                .expect("partial authentication response")
                .status(),
            StatusCode::UNAUTHORIZED,
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(signed_calls.load(Ordering::SeqCst), 1);
    }

    #[cfg(feature = "app_api")]
    #[tokio::test]
    async fn canonical_body_zero_limit_get_rejects_nonempty_bodies() {
        use axum::{Extension, extract::DefaultBodyLimit};
        use std::sync::Arc;

        let _guard = crate::tests_runtime_handlers::app_auth_test_guard(
            crate::app_auth::CanonicalRequestAuthConfig::default(),
        );
        let key_pair = crate::tests_runtime_handlers::checked_torii_test_ed25519_keypair(
            0x74,
            "derive zero-body GET authentication test key",
        );
        let account = iroha_data_model::account::AccountId::new(key_pair.public_key().clone());
        let app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world(
            crate::tests_runtime_handlers::world_with_account(&account),
        );
        const ROUTE: RouteDescriptor = RouteDescriptor::new(
            "test.zero_body_account",
            HttpMethod::Get,
            "/v1/tests/zero-body-account",
            ApiSurface::Public,
            Listener::Torii,
            RouteEffect::ReadOnly,
            AdmissionPolicy::AuthenticatedAccount,
        )
        .with_authentication(AuthenticationPolicy::CanonicalAccountSignature);
        let calls = Arc::new(AtomicUsize::new(0));
        let handler_calls = Arc::clone(&calls);
        let mut builder = RouterBuilder::new(
            app.clone(),
            RouteCatalog::new(&[ROUTE]),
            EnabledFeatures::none(),
        )
        .expect("valid zero-body catalog");
        builder.route(
            &ROUTE,
            catalog_get(
                move |Extension(_verified): Extension<
                    crate::app_auth::VerifiedCanonicalRequest,
                >| {
                    let calls = Arc::clone(&handler_calls);
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        StatusCode::NO_CONTENT
                    }
                },
            )
            .layer(DefaultBodyLimit::max(1024))
            .authenticated_canonical_account_body(app.clone(), 0),
        );
        let (router, _) = builder.finish().expect("sealed zero-body route");
        let router = router.with_state(app);
        let uri: axum::http::Uri = ROUTE.path().parse().expect("route URI");
        for method in [Method::HEAD, Method::POST] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(uri.clone())
                        .body(Body::from("unadmitted body"))
                        .expect("wrong-method authenticated route request"),
                )
                .await
                .expect("wrong-method response");
            assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
            assert_eq!(response.headers()[axum::http::header::ALLOW], "GET");
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
        let unsigned = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(uri.clone())
                    .body(Body::empty())
                    .expect("unsigned GET request"),
            )
            .await
            .expect("unsigned GET response");
        assert_eq!(unsigned.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        for (body, expected_status) in [
            (Vec::new(), StatusCode::NO_CONTENT),
            (vec![b'x'], StatusCode::PAYLOAD_TOO_LARGE),
        ] {
            let headers = crate::tests_runtime_handlers::signed_app_headers(
                &account,
                &key_pair,
                &Method::GET,
                &uri,
                &body,
            );
            let mut request = Request::builder()
                .method(Method::GET)
                .uri(uri.clone())
                .body(Body::from(body))
                .expect("signed GET request");
            request.headers_mut().extend(headers);
            assert_eq!(
                router
                    .clone()
                    .oneshot(request)
                    .await
                    .expect("GET response")
                    .status(),
                expected_status,
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn canonical_signed_body_requires_the_sealed_handler_witness() {
        let mut builder = RouterBuilder::new(
            (),
            RouteCatalog::new(&[SIGNED_BODY_AUTHENTICATED]),
            EnabledFeatures::none(),
        )
        .expect("valid signed-body catalog");
        builder.route(
            &SIGNED_BODY_AUTHENTICATED,
            catalog_post(|| async {}).layer(axum::Extension("self-signed-payload")),
        );
        let errors = builder
            .finish()
            .expect_err("arbitrary middleware or a payload self-signature is not a witness");
        assert!(errors.iter().any(|error| matches!(
            error,
            RouterAssemblyError::AuthenticationMismatch {
                stable_route_id: "test.signed_body_authenticated",
                expected: AuthenticationPolicy::CanonicalSignedBody,
                actual: AuthenticationPolicy::ToriiDefault,
            }
        )));
        let mut builder = RouterBuilder::new(
            (),
            RouteCatalog::new(&[SIGNED_BODY_AUTHENTICATED]),
            EnabledFeatures::none(),
        )
        .expect("valid signed-body catalog");
        builder.route(
            &SIGNED_BODY_AUTHENTICATED,
            catalog_post(|| async {})
                .authenticated_in_handler(HandlerAuthentication::CanonicalSignedBody),
        );
        let _ = builder
            .finish()
            .expect("the reviewed canonical signed-body witness must mount");
    }
    #[test]
    fn manifest_conditional_content_witness_matches_only_its_catalog_policy() {
        let mut builder = RouterBuilder::new(
            (),
            RouteCatalog::new(&[MANIFEST_CONDITIONAL_CONTENT]),
            EnabledFeatures::none(),
        )
        .expect("valid catalog");
        builder.route(
            &MANIFEST_CONDITIONAL_CONTENT,
            catalog_get(|| async {})
                .authenticated_in_handler(HandlerAuthentication::ManifestConditionalContent),
        );
        let (_, manifest) = builder
            .finish()
            .expect("manifest-conditional content witness must mount");
        assert_eq!(manifest.explicit_routes(), &[MANIFEST_CONDITIONAL_CONTENT]);
    }
    #[cfg(feature = "app_api")]
    #[test]
    fn proof_body_authentication_mounts_the_exact_catalog_witness() {
        let app = crate::mk_app_state_for_tests();
        let mut builder = RouterBuilder::new(
            app.clone(),
            RouteCatalog::new(&[ACCOUNT_AUTHENTICATED]),
            EnabledFeatures::none(),
        )
        .expect("valid account-authenticated catalog");
        builder.route(
            &ACCOUNT_AUTHENTICATED,
            catalog_post(|| async { StatusCode::NO_CONTENT })
                .authenticated_canonical_account_proof_body(app, 1024),
        );
        let _ = builder
            .finish()
            .expect("proof-body authentication must satisfy the exact catalog policy");
    }
    #[cfg(feature = "app_api")]
    #[test]
    fn optional_account_body_authentication_mounts_the_exact_catalog_witness() {
        let app = crate::mk_app_state_for_tests();
        let mut builder = RouterBuilder::new(
            app.clone(),
            RouteCatalog::new(&[OPTIONAL_DATASPACE_AUTHENTICATED]),
            EnabledFeatures::none(),
        )
        .expect("valid optional dataspace catalog");
        builder.route(
            &OPTIONAL_DATASPACE_AUTHENTICATED,
            catalog_post(|| async { StatusCode::NO_CONTENT })
                .optionally_authenticated_canonical_account_body(app, 1024),
        );
        let _ = builder
            .finish()
            .expect("optional account-body authentication must satisfy the exact catalog policy");
    }
    #[test]
    fn wrong_handler_authentication_witness_is_rejected() {
        let mut builder =
            RouterBuilder::new((), RouteCatalog::new(&[HANDSHAKE]), EnabledFeatures::none())
                .expect("valid catalog");
        builder.route(
            &HANDSHAKE,
            catalog_get(|| async {})
                .authenticated_in_handler(HandlerAuthentication::OperatorCredentialExchange),
        );
        let errors = builder
            .finish()
            .expect_err("a different handler-owned policy must fail");
        assert!(errors.iter().any(|error| matches!(
            error,
            RouterAssemblyError::AuthenticationMismatch {
                stable_route_id: "test.handshake",
                expected: AuthenticationPolicy::ProtocolHandshake,
                actual: AuthenticationPolicy::OperatorCredentialExchange,
            }
        )));
    }
    #[test]
    fn special_authentication_type_state_cannot_receive_outer_middleware() {
        fn assert_layerable<T: LayerableAuthentication>() {}
        struct Invalid;
        trait AmbiguousIfLayerable<A> {
            fn marker() {}
        }
        impl<T: ?Sized> AmbiguousIfLayerable<()> for T {}
        impl<T: ?Sized + LayerableAuthentication> AmbiguousIfLayerable<Invalid> for T {}
        assert_layerable::<ToriiDefaultAuthentication>();
        assert_layerable::<UnauthenticatedRoute>();
        let _ = <SealedAuthentication as AmbiguousIfLayerable<_>>::marker;
    }
    #[cfg(feature = "app_api")]
    #[tokio::test]
    async fn operator_witness_installs_signature_validation_and_replay_protection() {
        let app = crate::mk_app_state_for_tests();
        let signer = app.da_receipt_signer.clone();
        let mut builder = RouterBuilder::new(
            app.clone(),
            RouteCatalog::new(&[OPERATOR]),
            EnabledFeatures::none(),
        )
        .expect("valid catalog");
        builder.route(
            &OPERATOR,
            catalog_get(|| async { StatusCode::OK })
                .layer(axum::middleware::from_fn(short_circuit_success))
                .authenticated_operator(app.clone()),
        );
        let (router, _) = builder.finish().expect("operator route must mount");
        let network_id = *app.state.network_id_ref();
        let router = router.with_state(app);
        let unsigned = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(OPERATOR.path())
                    .body(Body::empty())
                    .expect("unsigned request"),
            )
            .await
            .expect("unsigned response");
        assert_eq!(unsigned.status(), StatusCode::UNAUTHORIZED);
        let uri = OPERATOR.path().parse::<crate::Uri>().expect("operator URI");
        let signed_headers = operator_signatures::signed_request_headers(
            &signer,
            &network_id,
            &crate::Method::GET,
            &uri,
            &[],
        )
        .expect("operator request signature");
        let signed_request = || {
            let mut request = Request::builder()
                .uri(uri.clone())
                .body(Body::empty())
                .expect("signed request");
            request.headers_mut().extend(signed_headers.clone());
            request
        };
        let accepted = router
            .clone()
            .oneshot(signed_request())
            .await
            .expect("signed response");
        assert_eq!(
            accepted.status(),
            StatusCode::IM_A_TEAPOT,
            "pre-auth middleware may short-circuit only after operator authentication succeeds"
        );
        let replayed = router
            .oneshot(signed_request())
            .await
            .expect("replayed response");
        assert_eq!(replayed.status(), StatusCode::UNAUTHORIZED);
    }
}
