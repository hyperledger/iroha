//! Orthogonal semantics published with MCP tool descriptors.
//!
//! These types intentionally keep operation, authority, mutation risk, retry behavior, world
//! boundary, sensitivity, and signing requirements independent. The existing `ToolEffect` remains
//! a construction-time compatibility adapter while registry entries migrate to explicit
//! semantics.

use iroha_torii_shared::route_catalog::{
    AdmissionPolicy, ApiSurface, AuthenticationPolicy, RouteDescriptor,
};
use norito::json::{Map, Value};

/// Schema version for `_meta["iroha/semantics"]`.
const TOOL_SEMANTICS_SCHEMA_VERSION: u16 = 1;

/// The kind of work a tool performs at the Torii MCP boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::mcp) enum OperationKind {
    /// Observe state without changing it.
    Observe,
    /// Construct an unsigned artifact without changing Torii or ledger state.
    Construct,
    /// Mutate Torii-local, ledger, or external state.
    Mutate,
}

impl OperationKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Construct => "construct",
            Self::Mutate => "mutate",
        }
    }
}

/// Principal class required to invoke a tool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::mcp) enum AuthorityClass {
    /// No route-specific credential is required.
    Public,
    /// The configured Torii listener credential is required.
    ListenerCredential,
    /// Anonymous public-dataspace access, optionally expanded by account authentication.
    DataspaceVisible,
    /// A canonical ledger-account request signature is required.
    Account,
    /// A signed request body or another identity-bound proof is required.
    SignedBody,
    /// A non-ledger protocol principal is authenticated by its handshake.
    ProtocolPrincipal,
    /// Exact-network operator authority is required.
    Operator,
}

impl AuthorityClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::ListenerCredential => "listener_credential",
            Self::DataspaceVisible => "dataspace_visible",
            Self::Account => "account",
            Self::SignedBody => "signed_body",
            Self::ProtocolPrincipal => "protocol_principal",
            Self::Operator => "operator",
        }
    }

    /// Return whether satisfying this authority always requires a signature produced outside MCP.
    pub(in crate::mcp) const fn requires_external_signature(self) -> bool {
        matches!(self, Self::Account | Self::SignedBody | Self::Operator)
    }
}

/// Strongest state-change behavior reachable through a tool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::mcp) enum MutationNature {
    /// The tool does not mutate state.
    None,
    /// The tool is explicitly audited to add state without reducing, removing, or replacing it.
    AdditiveOnly,
    /// The tool may reduce, remove, replace, transfer, revoke, cancel, or otherwise overwrite state.
    MayReduceRemoveOrOverwrite,
}

impl MutationNature {
    const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::AdditiveOnly => "additive_only",
            Self::MayReduceRemoveOrOverwrite => "may_reduce_remove_or_overwrite",
        }
    }
}

/// Classify mutation nature while legacy descriptors migrate to explicit registry entries.
pub(in crate::mcp) const fn mutation_nature_for_operation(
    operation: OperationKind,
    audited_additive_only: bool,
) -> MutationNature {
    match operation {
        OperationKind::Observe | OperationKind::Construct => MutationNature::None,
        OperationKind::Mutate if audited_additive_only => MutationNature::AdditiveOnly,
        OperationKind::Mutate => MutationNature::MayReduceRemoveOrOverwrite,
    }
}

/// Safety of retrying the same tool arguments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::mcp) enum RetrySemantics {
    /// Retrying cannot add another side effect.
    Safe,
    /// A stable identity makes repeated submissions converge on one effect.
    ExactIdentityDeduplicated,
    /// Retrying may add another effect or has not been proven safe.
    Unsafe,
}

impl RetrySemantics {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Safe => "safe",
            Self::ExactIdentityDeduplicated => "exact_identity_deduplicated",
            Self::Unsafe => "unsafe",
        }
    }
}

/// Furthest state boundary that a tool can reach.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::mcp) enum WorldBoundary {
    /// State owned by this Torii process.
    ToriiLocal,
    /// State inside the configured Iroha network.
    IrohaNetwork,
    /// An entity outside the configured Iroha network.
    External,
}

impl WorldBoundary {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ToriiLocal => "torii_local",
            Self::IrohaNetwork => "iroha_network",
            Self::External => "external",
        }
    }
}

/// Whether invocation or output may carry privileged or private material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::mcp) enum Sensitivity {
    /// Ordinary public or non-sensitive material.
    Normal,
    /// Privileged, identity-bound, restricted, or external-system material.
    Sensitive,
}

impl Sensitivity {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Sensitive => "sensitive",
        }
    }
}

/// Standard MCP tool-annotation hints derived from the orthogonal semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "MCP defines four orthogonal boolean annotations on every tool."
)]
pub(in crate::mcp) struct ToolAnnotations {
    /// Whether invoking the tool leaves server and ledger state unchanged.
    pub(super) read_only: bool,
    /// Whether a mutation can reduce, remove, or overwrite state.
    pub(super) destructive: bool,
    /// Whether retrying the same arguments cannot add another effect.
    pub(super) idempotent: bool,
    /// Whether the tool can interact outside the configured Iroha network.
    pub(super) open_world: bool,
}

impl ToolAnnotations {
    /// Encode these hints using the standard MCP annotation field names.
    pub(in crate::mcp) fn into_value(self) -> Value {
        norito::json!({
            "readOnlyHint": (self.read_only),
            "destructiveHint": (self.destructive),
            "idempotentHint": (self.idempotent),
            "openWorldHint": (self.open_world)
        })
    }
}

/// Orthogonal semantic classification for one MCP tool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::mcp) struct ToolSemantics {
    operation: OperationKind,
    authority: AuthorityClass,
    mutation: MutationNature,
    retry: RetrySemantics,
    world: WorldBoundary,
    sensitivity: Sensitivity,
    requires_external_signature: bool,
}

impl ToolSemantics {
    /// Construct a semantic classification, rejecting inconsistent operation/mutation pairs.
    pub(in crate::mcp) fn try_new(
        operation: OperationKind,
        authority: AuthorityClass,
        mutation: MutationNature,
        retry: RetrySemantics,
        world: WorldBoundary,
        sensitivity: Sensitivity,
        requires_external_signature: bool,
    ) -> Result<Self, &'static str> {
        let mutation_is_none = mutation == MutationNature::None;
        if matches!(operation, OperationKind::Observe | OperationKind::Construct)
            != mutation_is_none
        {
            return Err(
                "observe/construct operations require mutation=none; mutate operations require a non-none mutation",
            );
        }
        Ok(Self {
            operation,
            authority,
            mutation,
            retry,
            world,
            sensitivity,
            requires_external_signature,
        })
    }

    /// Return the operation kind.
    pub(in crate::mcp) const fn operation(self) -> OperationKind {
        self.operation
    }

    /// Return the authority class.
    pub(in crate::mcp) const fn authority(self) -> AuthorityClass {
        self.authority
    }

    /// Derive standard MCP tool-annotation hints.
    pub(in crate::mcp) const fn annotations(self) -> ToolAnnotations {
        ToolAnnotations {
            read_only: matches!(
                self.operation,
                OperationKind::Observe | OperationKind::Construct
            ),
            destructive: matches!(self.mutation, MutationNature::MayReduceRemoveOrOverwrite),
            idempotent: matches!(
                self.retry,
                RetrySemantics::Safe | RetrySemantics::ExactIdentityDeduplicated
            ),
            // The configured Iroha network is one closed ledger domain. Only tools that cross
            // beyond that domain advertise MCP's open-world hint.
            open_world: matches!(self.world, WorldBoundary::External),
        }
    }

    /// Encode the versioned Iroha-specific metadata object.
    pub(in crate::mcp) fn metadata(self) -> Value {
        let mut metadata = Map::new();
        metadata.insert(
            "schemaVersion".into(),
            Value::from(TOOL_SEMANTICS_SCHEMA_VERSION),
        );
        metadata.insert(
            "operation".into(),
            Value::String(self.operation.as_str().to_owned()),
        );
        metadata.insert(
            "authority".into(),
            Value::String(self.authority.as_str().to_owned()),
        );
        metadata.insert(
            "mutation".into(),
            Value::String(self.mutation.as_str().to_owned()),
        );
        metadata.insert(
            "retry".into(),
            Value::String(self.retry.as_str().to_owned()),
        );
        metadata.insert(
            "world".into(),
            Value::String(self.world.as_str().to_owned()),
        );
        metadata.insert(
            "sensitivity".into(),
            Value::String(self.sensitivity.as_str().to_owned()),
        );
        metadata.insert(
            "requiresExternalSignature".into(),
            Value::Bool(self.requires_external_signature),
        );
        Value::Object(metadata)
    }
}

/// Classify route authority without conflating it with operation effects.
pub(in crate::mcp) fn authority_for_route(route: &RouteDescriptor) -> AuthorityClass {
    if route.surface() == ApiSurface::Operator
        || route.admission() == AdmissionPolicy::Operator
        || matches!(
            route.authentication(),
            AuthenticationPolicy::OperatorSignature
                | AuthenticationPolicy::OperatorCredentialExchange
        )
    {
        return AuthorityClass::Operator;
    }

    let authentication = match route.authentication() {
        AuthenticationPolicy::ToriiDefault
        | AuthenticationPolicy::PrivateRootOwnerToken
        | AuthenticationPolicy::OnboardingToken => AuthorityClass::ListenerCredential,
        AuthenticationPolicy::CanonicalAccountSignature => AuthorityClass::Account,
        AuthenticationPolicy::OptionalCanonicalAccountSignature
        | AuthenticationPolicy::ManifestConditionalContent => AuthorityClass::DataspaceVisible,
        AuthenticationPolicy::CanonicalSignedBody
        | AuthenticationPolicy::IdentityBoundSignature
        | AuthenticationPolicy::NestedRouteAuthentication => AuthorityClass::SignedBody,
        AuthenticationPolicy::ProtocolHandshake => AuthorityClass::ProtocolPrincipal,
        AuthenticationPolicy::OperatorSignature
        | AuthenticationPolicy::OperatorCredentialExchange => AuthorityClass::Operator,
        AuthenticationPolicy::Unauthenticated => AuthorityClass::Public,
    };
    match route.admission() {
        AdmissionPolicy::AuthenticatedAccount => match authentication {
            AuthorityClass::SignedBody => AuthorityClass::SignedBody,
            _ => AuthorityClass::Account,
        },
        AdmissionPolicy::DataspaceVisible => AuthorityClass::DataspaceVisible,
        AdmissionPolicy::AuthenticatedProtocolPrincipal => AuthorityClass::ProtocolPrincipal,
        AdmissionPolicy::ValidatorRosterMember
        | AdmissionPolicy::GovernedAuditor
        | AdmissionPolicy::TargetRoute => AuthorityClass::SignedBody,
        AdmissionPolicy::Public => authentication,
        AdmissionPolicy::Operator => AuthorityClass::Operator,
    }
}

/// Classify the semantic world boundary from an exact curated name and Torii route.
pub(in crate::mcp) fn world_boundary_for_tool(name: &str, path: &str) -> WorldBoundary {
    if name.starts_with("iroha.connect.")
        || name.starts_with("iroha.vpn.")
        || name.starts_with("iroha.iso20022.")
        || name.starts_with("iroha.bridge.")
        || path.starts_with("/v1/connect/")
        || path.starts_with("/v1/vpn/")
        || path.starts_with("/v1/iso20022/")
        || path.starts_with("/v1/bridge/")
    {
        return WorldBoundary::External;
    }
    if matches!(
        name,
        "iroha.health"
            | "iroha.node.capabilities"
            | "iroha.runtime.abi.active"
            | "iroha.runtime.abi.hash"
            | "iroha.runtime.metrics"
    ) || matches!(
        path,
        "/health"
            | "/v1/node/capabilities"
            | "/v1/runtime/abi/active"
            | "/v1/runtime/abi/hash"
            | "/v1/runtime/metrics"
    ) {
        return WorldBoundary::ToriiLocal;
    }
    WorldBoundary::IrohaNetwork
}

/// Classify whether a tool's invocation or output is sensitive.
pub(in crate::mcp) const fn sensitivity_for(
    authority: AuthorityClass,
    world: WorldBoundary,
    surface: Option<ApiSurface>,
) -> Sensitivity {
    if matches!(world, WorldBoundary::External)
        || matches!(
            authority,
            AuthorityClass::DataspaceVisible
                | AuthorityClass::Account
                | AuthorityClass::SignedBody
                | AuthorityClass::ProtocolPrincipal
                | AuthorityClass::Operator
        )
        || matches!(surface, Some(ApiSurface::Diagnostic | ApiSurface::Operator))
    {
        Sensitivity::Sensitive
    } else {
        Sensitivity::Normal
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::{
        iroha_runtime_upgrades_list_tool, iroha_transactions_submit_tool, tool_semantics,
    };

    fn semantics(
        operation: OperationKind,
        mutation: MutationNature,
        retry: RetrySemantics,
        world: WorldBoundary,
    ) -> ToolSemantics {
        ToolSemantics::try_new(
            operation,
            AuthorityClass::Public,
            mutation,
            retry,
            world,
            Sensitivity::Normal,
            false,
        )
        .expect("valid test semantics")
    }

    #[test]
    fn operation_and_mutation_invariants_fail_closed() {
        assert!(
            ToolSemantics::try_new(
                OperationKind::Observe,
                AuthorityClass::Public,
                MutationNature::AdditiveOnly,
                RetrySemantics::Safe,
                WorldBoundary::ToriiLocal,
                Sensitivity::Normal,
                false,
            )
            .is_err()
        );
        assert!(
            ToolSemantics::try_new(
                OperationKind::Mutate,
                AuthorityClass::Public,
                MutationNature::None,
                RetrySemantics::Unsafe,
                WorldBoundary::IrohaNetwork,
                Sensitivity::Normal,
                false,
            )
            .is_err()
        );
    }

    #[test]
    fn annotations_keep_mutation_and_retry_semantics_independent() {
        let additive = semantics(
            OperationKind::Mutate,
            MutationNature::AdditiveOnly,
            RetrySemantics::Unsafe,
            WorldBoundary::IrohaNetwork,
        )
        .annotations();
        assert!(!additive.read_only);
        assert!(!additive.destructive);
        assert!(!additive.idempotent);
        assert!(!additive.open_world);

        let destructive_but_deduplicated = semantics(
            OperationKind::Mutate,
            MutationNature::MayReduceRemoveOrOverwrite,
            RetrySemantics::ExactIdentityDeduplicated,
            WorldBoundary::External,
        )
        .annotations();
        assert!(!destructive_but_deduplicated.read_only);
        assert!(destructive_but_deduplicated.destructive);
        assert!(destructive_but_deduplicated.idempotent);
        assert!(destructive_but_deduplicated.open_world);
    }

    #[test]
    fn construct_is_read_only_at_the_server_and_requires_no_mutation() {
        let constructed = ToolSemantics::try_new(
            OperationKind::Construct,
            AuthorityClass::Public,
            MutationNature::None,
            RetrySemantics::Safe,
            WorldBoundary::IrohaNetwork,
            Sensitivity::Normal,
            true,
        )
        .expect("construct semantics");
        assert_eq!(
            constructed.annotations().into_value(),
            norito::json!({
                "readOnlyHint": true,
                "destructiveHint": false,
                "idempotentHint": true,
                "openWorldHint": false
            })
        );
    }

    #[test]
    fn custom_metadata_is_versioned_and_orthogonal() {
        let classified = ToolSemantics::try_new(
            OperationKind::Mutate,
            AuthorityClass::Operator,
            MutationNature::MayReduceRemoveOrOverwrite,
            RetrySemantics::Unsafe,
            WorldBoundary::IrohaNetwork,
            Sensitivity::Sensitive,
            true,
        )
        .expect("operator mutation semantics");
        assert_eq!(
            classified.metadata(),
            norito::json!({
                "schemaVersion": 1,
                "operation": "mutate",
                "authority": "operator",
                "mutation": "may_reduce_remove_or_overwrite",
                "retry": "unsafe",
                "world": "iroha_network",
                "sensitivity": "sensitive",
                "requiresExternalSignature": true
            })
        );
    }

    #[test]
    fn signed_transaction_submit_is_destructive_but_identity_deduplicated() {
        let tool = iroha_transactions_submit_tool();
        let classified = tool_semantics(&tool);
        assert_eq!(classified.operation(), OperationKind::Mutate);
        assert_eq!(classified.authority(), AuthorityClass::SignedBody);
        let annotations = classified.annotations();
        assert!(!annotations.read_only);
        assert!(annotations.destructive);
        assert!(annotations.idempotent);
        assert!(!annotations.open_world);
        assert_eq!(
            classified.metadata()["requiresExternalSignature"].as_bool(),
            Some(true)
        );
        let descriptor = tool.descriptor();
        assert_eq!(
            descriptor["annotations"],
            classified.annotations().into_value()
        );
        assert_eq!(
            descriptor["_meta"]["iroha/semantics"],
            classified.metadata()
        );
    }

    #[test]
    fn operator_read_keeps_authority_separate_from_operation() {
        let classified = tool_semantics(&iroha_runtime_upgrades_list_tool());
        assert_eq!(classified.operation(), OperationKind::Observe);
        assert_eq!(classified.authority(), AuthorityClass::Operator);
        let annotations = classified.annotations();
        assert!(annotations.read_only);
        assert!(!annotations.destructive);
        assert!(annotations.idempotent);
        assert_eq!(
            classified.metadata()["sensitivity"].as_str(),
            Some("sensitive")
        );
    }
}
