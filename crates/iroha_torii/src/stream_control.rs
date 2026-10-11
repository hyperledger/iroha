//! Persistent Explorer control custody, separate from every complete block query owner.
//!
//! Native control layouts and one exact retained caller are admitted directly from the original
//! host pool. This capability cannot construct a query reservation or grant decoder authority.
//! Authentication/revalidation borrows a separately acquired complete query owner synchronously.

use std::{
    fmt,
    pin::Pin,
    task::{Context, Poll},
};

use axum::body::{Body, Bytes};
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use iroha_allocation::shared::Shared;
use iroha_core::state::{AuthorizationRead, StorageReadOnly, WorldReadOnly};
use iroha_data_model::{account::AccountId, nexus::MAX_ACTIVE_EXECUTION_LANES};
use iroha_executor_data_model::permission::query::{
    CanReadAllLedgerData, CanReadRestrictedDataspace,
};
use iroha_model_base::topology::DataSpaceId;
use tokio::sync::OwnedSemaphorePermit;

use crate::{Error, SharedAppState};

fn capacity() -> Error {
    crate::native_projection_response::capacity()
}

/// One sorted, allocation-free subset of the actual finite active route catalogue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FixedRouteScope {
    ids: [DataSpaceId; MAX_ACTIVE_EXECUTION_LANES],
    len: usize,
}

impl Default for FixedRouteScope {
    fn default() -> Self {
        Self {
            ids: [DataSpaceId::UNIVERSAL; MAX_ACTIVE_EXECUTION_LANES],
            len: 0,
        }
    }
}

impl FixedRouteScope {
    pub(crate) fn insert(&mut self, id: DataSpaceId) -> Result<(), Error> {
        let Err(index) = self.as_slice().binary_search(&id) else {
            return Ok(());
        };
        if self.len == self.ids.len() {
            return Err(capacity());
        }
        self.ids.copy_within(index..self.len, index + 1);
        self.ids[index] = id;
        self.len += 1;
        Ok(())
    }

    pub(crate) fn as_slice(&self) -> &[DataSpaceId] {
        &self.ids[..self.len]
    }
}

struct CapturedControl {
    app: SharedAppState,
    caller: Option<AccountId>,
    baseline: FixedRouteScope,
    can_read_all: bool,
    admitted_height: u64,
}

/// The original native shared control and its post-deallocation weighted-pool lease.
#[derive(Clone)]
pub(crate) struct StreamControlOwner {
    captured: Shared<CapturedControl, OwnedSemaphorePermit>,
}

struct ScopeReclaim {
    _permit: OwnedSemaphorePermit,
    _owner: StreamControlOwner,
}

/// A current fixed scope under its own exact native layout, without a BTreeSet copy.
#[derive(Clone)]
pub(crate) struct FixedScopeOwner {
    scope: Shared<FixedRouteScope, ScopeReclaim>,
}

impl FixedScopeOwner {
    pub(crate) fn as_slice(&self) -> &[DataSpaceId] {
        self.scope.as_slice()
    }
}

impl fmt::Debug for FixedScopeOwner {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_slice().fmt(out)
    }
}

impl PartialEq for FixedScopeOwner {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}
impl Eq for FixedScopeOwner {}

/// Explorer's persistent reader captures only an exactly paid caller and finite route scope.
#[derive(Clone)]
pub(crate) struct ExplorerReadContext {
    owner: StreamControlOwner,
    #[cfg(test)]
    fixed_visibility: Option<crate::routing::DataspaceReadVisibility>,
}

impl ExplorerReadContext {
    pub(crate) fn from_headers(
        app: &SharedAppState,
        headers: &axum::http::HeaderMap,
        method: &axum::http::Method,
        uri: &axum::http::Uri,
    ) -> Result<Self, Error> {
        // This real transient owner precedes alias/witness/native protected-state decoding.
        // Only its exact retained caller is transferred into the much smaller control owner.
        let auth = crate::history_producer::HistoryProducerOwner::authentication_read(app)?;
        auth.scope(|| {
            let verified = crate::app_auth::verify_canonical_network_request(
                &app.state,
                app.state.network_id_ref(),
                headers,
                method,
                uri,
                &[],
                None,
                auth.allocation_context(),
            )?;
            let caller = verified.as_ref().map(|verified| &verified.account);
            let (scope, all, height) = app
                .state
                .try_with_authorization_view(auth.allocation_context(), |view| {
                    let (scope, all) = authorized_scope(&view, caller)?;
                    let height = u64::try_from(view.height()).map_err(|_| capacity())?;
                    Ok::<_, Error>((scope, all, height))
                })
                .map_err(crate::app_auth::authorization_view_error)??;
            let owner = StreamControlOwner::capture(app.clone(), caller, scope, all, height)?;
            Ok(Self {
                owner,
                #[cfg(test)]
                fixed_visibility: None,
            })
        })
    }

    pub(crate) fn owner(&self) -> &StreamControlOwner {
        &self.owner
    }
    pub(crate) fn admitted_height(&self) -> u64 {
        self.owner.admitted_height()
    }

    pub(crate) fn current_visibility(
        &self,
    ) -> Result<crate::routing::DataspaceReadVisibility, Error> {
        #[cfg(test)]
        if let Some(fixed) = &self.fixed_visibility {
            return Ok(fixed.clone());
        }
        let app = self.owner.app();
        let auth = crate::history_producer::HistoryProducerOwner::authentication_read(app)?;
        let (scope, all) = auth
            .scope(|| {
                app.state
                    .try_with_authorization_view(auth.allocation_context(), |view| {
                        authorized_scope(&view, self.owner.caller())
                    })
            })
            .map_err(crate::app_auth::authorization_view_error)??;
        if self.owner.can_read_all() && !all
            || self
                .owner
                .baseline()
                .as_slice()
                .iter()
                .any(|id| scope.as_slice().binary_search(id).is_err())
        {
            return Err(Error::AppUnauthorized {
                code: "stream_authorization_revoked",
                message: "Stream authorization was revoked.".into(),
            });
        }
        Ok(crate::routing::DataspaceReadVisibility::from_fixed_scope(
            self.owner.scope_owner(scope)?,
            all,
        ))
    }

    #[cfg(test)]
    pub(crate) fn all_for_tests_at(height: u64) -> Self {
        let owner = StreamControlOwner::capture(
            crate::mk_app_state_for_tests(),
            None,
            FixedRouteScope::default(),
            true,
            height,
        )
        .unwrap();
        Self {
            owner,
            fixed_visibility: Some(crate::routing::DataspaceReadVisibility::all_for_tests()),
        }
    }
}

fn account_permission_matches(
    world: &impl WorldReadOnly,
    caller: &AccountId,
    matches: impl Fn(&iroha_data_model::permission::Permission) -> Result<bool, Error>,
) -> Result<bool, Error> {
    if let Ok(permissions) = world.account_permissions_iter(caller) {
        for permission in permissions {
            if matches(permission)? {
                return Ok(true);
            }
        }
    }
    for role in world.account_roles_iter(caller) {
        if let Some(role) = world.roles().get(role) {
            for permission in role.permissions() {
                if matches(permission)? {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}
fn scalar_permission<T: norito::json::JsonSerialize>(
    permission: &iroha_data_model::permission::Permission,
    name: &str,
    target: &T,
) -> Result<bool, Error> {
    if permission.name() != name {
        return Ok(false);
    }
    struct ExactPayload<'a> {
        expected: &'a [u8],
        position: usize,
        matches: bool,
    }
    impl norito::json::JsonWriteSink for ExactPayload<'_> {
        fn push(&mut self, value: char) -> Result<(), norito::json::BoundedJsonError> {
            let mut scratch = [0; 4];
            self.push_str(value.encode_utf8(&mut scratch))
        }
        fn push_str(&mut self, value: &str) -> Result<(), norito::json::BoundedJsonError> {
            let end = self
                .position
                .checked_add(value.len())
                .ok_or(norito::json::BoundedJsonError::LengthMismatch)?;
            self.matches &= self.expected.get(self.position..end) == Some(value.as_bytes());
            self.position = end;
            Ok(())
        }
    }
    let mut output = ExactPayload {
        expected: permission.payload().get().as_bytes(),
        position: 0,
        matches: true,
    };
    target
        .json_serialize_to(&mut output)
        .map_err(|_| capacity())?;
    Ok(output.matches && output.position == output.expected.len())
}
fn can_read_all(world: &impl WorldReadOnly, caller: &AccountId) -> Result<bool, Error> {
    account_permission_matches(world, caller, |permission| {
        scalar_permission(permission, "CanReadAllLedgerData", &CanReadAllLedgerData)
    })
}
fn can_read_dataspace(
    world: &impl WorldReadOnly,
    caller: &AccountId,
    id: DataSpaceId,
) -> Result<bool, Error> {
    account_permission_matches(world, caller, |permission| {
        scalar_permission(
            permission,
            "CanReadRestrictedDataspace",
            &CanReadRestrictedDataspace { dataspace: id },
        )
    })
}
fn authorized_scope(
    view: &AuthorizationRead<'_, '_>,
    caller: Option<&AccountId>,
) -> Result<(FixedRouteScope, bool), Error> {
    use iroha_data_model::{block::consensus::SumeragiRootScope, nexus::LaneVisibility};
    let world = view.world();
    if caller.is_some_and(|caller| world.accounts().get(caller).is_none()) {
        return Err(Error::AppUnauthorized {
            code: "stream_authorization_revoked",
            message: "Stream authorization was revoked.".into(),
        });
    }
    let all = match caller {
        Some(caller) => can_read_all(world, caller)?,
        None => false,
    };
    let root = iroha_core::sumeragi::lanes::routing::committed_root_scope(world);
    let bindings = caller
        .and_then(|caller| world.accounts().get(caller))
        .and_then(|account| account.uaid())
        .and_then(|uaid| world.uaid_dataspaces().get(uaid));
    let mut scope = FixedRouteScope::default();
    // Visit only the authoritative finite active catalog. UAID bindings never form a new set.
    for lane in view.active_lanes() {
        let id = lane.dataspace_id;
        let own = if let Some(caller) = caller {
            can_read_dataspace(world, caller, id)?
        } else {
            false
        };
        let visible = match root {
            Some(SumeragiRootScope::Dataspace { dataspace_id, .. }) => {
                id == dataspace_id && caller.is_some() && (all || own)
            }
            Some(SumeragiRootScope::Global) => {
                lane.visibility == LaneVisibility::Public
                    || all
                    || bindings
                        .is_some_and(|bindings| bindings.iter().any(|(bound, _)| *bound == id))
                    || own
            }
            None => false,
        };
        if visible {
            scope.insert(id)?;
        }
    }
    Ok((scope, all))
}

impl StreamControlOwner {
    /// Transfer an authenticated scope only after its exact caller copy/control layout fit.
    /// The supplied original caller remains owned by the initial query until this copy completes.
    pub(crate) fn capture(
        app: SharedAppState,
        caller: Option<&AccountId>,
        baseline: FixedRouteScope,
        can_read_all: bool,
        admitted_height: u64,
    ) -> Result<Self, Error> {
        let mut bytes = Some(Shared::<CapturedControl, OwnedSemaphorePermit>::layout().size());
        if let Some(caller) = caller {
            caller
                .for_each_admission_clone_layout(|layout| {
                    bytes = bytes.and_then(|bytes| bytes.checked_add(layout.size()));
                })
                .map_err(|_| capacity())?;
        }
        let bytes = bytes
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(capacity)?;
        let permit = app
            .query_fanout_inflight
            .try_acquire_parts([bytes])
            .ok_or_else(capacity)?;
        // No graph is copied before the original host pool owns every native nested layout.
        let caller = caller
            .map(AccountId::try_clone_for_admission)
            .transpose()
            .map_err(|_| capacity())?;
        let captured = CapturedControl {
            app,
            caller,
            baseline,
            can_read_all,
            admitted_height,
        };
        let captured = Shared::try_new(captured, permit).map_err(|(captured, permit, _)| {
            drop(captured);
            drop(permit);
            capacity()
        })?;
        Ok(Self { captured })
    }

    pub(crate) fn caller(&self) -> Option<&AccountId> {
        self.captured.caller.as_ref()
    }
    pub(crate) fn app(&self) -> &SharedAppState {
        &self.captured.app
    }
    pub(crate) fn baseline(&self) -> &FixedRouteScope {
        &self.captured.baseline
    }
    pub(crate) fn can_read_all(&self) -> bool {
        self.captured.can_read_all
    }
    pub(crate) fn admitted_height(&self) -> u64 {
        self.captured.admitted_height
    }

    pub(crate) fn scope_owner(&self, scope: FixedRouteScope) -> Result<FixedScopeOwner, Error> {
        let layout = Shared::<FixedRouteScope, ScopeReclaim>::layout();
        let permit = self.acquire_layout(layout).map_err(|_| capacity())?;
        let reclaim = ScopeReclaim {
            _permit: permit,
            _owner: self.clone(),
        };
        let scope = Shared::try_new(scope, reclaim).map_err(|(_, reclaim, _)| {
            drop(reclaim);
            capacity()
        })?;
        Ok(FixedScopeOwner { scope })
    }

    fn acquire_layout(
        &self,
        layout: std::alloc::Layout,
    ) -> Result<OwnedSemaphorePermit, axum::Error> {
        let bytes = u64::try_from(layout.size()).map_err(|_| axum::Error::new(ControlCapacity))?;
        self.captured
            .app
            .query_fanout_inflight
            .try_acquire_parts([bytes])
            .ok_or_else(|| axum::Error::new(ControlCapacity))
    }

    fn data(&self, data: Bytes) -> Result<Bytes, axum::Error> {
        let layout = Bytes::owner_with_reclaim_layout::<Bytes, DataReclaim>();
        let permit = self.acquire_layout(layout)?;
        let reclaim = DataReclaim {
            _permit: permit,
            _owner: self.clone(),
        };
        Bytes::try_from_owner_with_reclaim(data, reclaim).map_err(|(data, reclaim)| {
            drop(data);
            drop(reclaim);
            axum::Error::new(ControlCapacity)
        })
    }

    /// Admit the first persistent typed stream body and token before native allocation.
    pub(crate) fn body<B>(&self, source: B) -> Result<Body, axum::Error>
    where
        B: HttpBody<Data = Bytes, Error = axum::Error> + Send + 'static,
    {
        let body_layout = Body::body_layout::<ControlBody<B>>();
        let token_layout = Body::reclaim_layout::<BodyReclaim>();
        let permits = self
            .captured
            .app
            .query_fanout_inflight
            .try_acquire_parts([
                u64::try_from(body_layout.size()).map_err(|_| axum::Error::new(ControlCapacity))?,
                u64::try_from(token_layout.size())
                    .map_err(|_| axum::Error::new(ControlCapacity))?,
            ])
            .ok_or_else(|| axum::Error::new(ControlCapacity))?;
        let source = ControlBody {
            source,
            owner: self.clone(),
            refused: false,
        };
        let reclaim = BodyReclaim {
            _permit: permits,
            _owner: self.clone(),
        };
        Body::try_new_with_reclaim(source, reclaim).map_err(|(source, reclaim)| {
            drop(source);
            drop(reclaim);
            axum::Error::new(ControlCapacity)
        })
    }
}

#[derive(Debug)]
struct ControlCapacity;
impl fmt::Display for ControlCapacity {
    fn fmt(&self, writer: &mut fmt::Formatter<'_>) -> fmt::Result {
        writer.write_str("stream control capacity exhausted")
    }
}
impl std::error::Error for ControlCapacity {}

struct DataReclaim {
    _permit: OwnedSemaphorePermit,
    _owner: StreamControlOwner,
}
struct BodyReclaim {
    _permit: OwnedSemaphorePermit,
    _owner: StreamControlOwner,
}
struct ControlBody<B> {
    source: B,
    owner: StreamControlOwner,
    refused: bool,
}

impl<B> HttpBody for ControlBody<B>
where
    B: HttpBody<Data = Bytes, Error = axum::Error>,
{
    type Data = Bytes;
    type Error = axum::Error;

    #[allow(unsafe_code)]
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        // SAFETY: the private source is structurally pinned, never moved after polling,
        // and this wrapper has no custom Drop. Other fields are not pinned projections.
        let this = unsafe { self.get_unchecked_mut() };
        if this.refused {
            return Poll::Ready(None);
        }
        // SAFETY: the source stays at this original pinned address through destruction.
        match unsafe { Pin::new_unchecked(&mut this.source) }.poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                let Some(data) = frame.data_ref() else {
                    this.refused = true;
                    return Poll::Ready(Some(Err(axum::Error::new(ControlCapacity))));
                };
                match this.owner.data(data.clone()) {
                    Ok(data) => Poll::Ready(Some(Ok(frame.map_data(|_| data)))),
                    Err(error) => {
                        this.refused = true;
                        Poll::Ready(Some(Err(error)))
                    }
                }
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.refused || self.source.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.source.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt as _, StreamBody};
    use std::sync::Arc;

    fn capture(app: &SharedAppState) -> StreamControlOwner {
        let mut scope = FixedRouteScope::default();
        scope.insert(DataSpaceId::UNIVERSAL).unwrap();
        StreamControlOwner::capture(app.clone(), None, scope, false, 1).unwrap()
    }

    #[test]
    fn fixed_route_scope_has_exact_catalogue_capacity_without_heap_growth() {
        let mut scope = FixedRouteScope::default();
        for id in (0..MAX_ACTIVE_EXECUTION_LANES).rev() {
            scope.insert(DataSpaceId::new(id as u64)).unwrap();
        }
        scope.insert(DataSpaceId::UNIVERSAL).unwrap();
        assert_eq!(scope.as_slice().len(), MAX_ACTIVE_EXECUTION_LANES);
        assert!(scope.as_slice().windows(2).all(|ids| ids[0] < ids[1]));
        assert!(
            scope
                .insert(DataSpaceId::new(MAX_ACTIVE_EXECUTION_LANES as u64))
                .is_err()
        );
    }

    #[test]
    fn scalar_permissions_compare_the_native_canonical_payload_without_a_json_tree() {
        let all: iroha_data_model::permission::Permission = CanReadAllLedgerData.into();
        assert!(scalar_permission(&all, "CanReadAllLedgerData", &CanReadAllLedgerData).unwrap());
        let token = CanReadRestrictedDataspace {
            dataspace: DataSpaceId::new(7),
        };
        let own: iroha_data_model::permission::Permission = token.into();
        assert!(scalar_permission(&own, "CanReadRestrictedDataspace", &token).unwrap());
        assert!(
            !scalar_permission(
                &own,
                "CanReadRestrictedDataspace",
                &CanReadRestrictedDataspace {
                    dataspace: DataSpaceId::new(8)
                }
            )
            .unwrap()
        );
        let invented = iroha_data_model::permission::Permission::new(
            "CanReadAllLedgerData".into(),
            norito::json!({"dataspace": 7}),
        );
        assert!(
            !scalar_permission(&invented, "CanReadAllLedgerData", &CanReadAllLedgerData).unwrap()
        );
        assert!(!scalar_permission(&own, "CanReadAllLedgerData", &CanReadAllLedgerData).unwrap());
    }

    #[test]
    fn stream_handshake_releases_transient_query_only_after_paid_control_transfer() {
        let app = crate::mk_app_state_for_tests();
        let available = app.query_fanout_inflight.available_bytes();
        let reader = ExplorerReadContext::from_headers(
            &app,
            &axum::http::HeaderMap::new(),
            &axum::http::Method::GET,
            &"/v1/explorer/blocks/stream".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(reader.admitted_height(), 0);
        let retained = usize::try_from(available - app.query_fanout_inflight.available_bytes())
            .expect("retained control allocation fits the host byte count");
        assert!(retained > 0 && retained < app.query_fanout_working_set_bytes);
        let current = reader.current_visibility().unwrap();
        drop(reader);
        assert!(app.query_fanout_inflight.available_bytes() < available);
        drop(current);
        assert_eq!(app.query_fanout_inflight.available_bytes(), available);
        let mut bare_account = axum::http::HeaderMap::new();
        bare_account.insert(
            crate::app_auth::HEADER_ACCOUNT,
            "wallet@universal".parse().unwrap(),
        );
        assert!(
            ExplorerReadContext::from_headers(
                &app,
                &bare_account,
                &axum::http::Method::GET,
                &"/v1/explorer/blocks/stream".parse().unwrap()
            )
            .is_err()
        );
        assert_eq!(app.query_fanout_inflight.available_bytes(), available);
    }

    #[test]
    fn stream_authorization_reports_real_malformed_catalog_as_internal() {
        use iroha_data_model::{
            ValidationFail,
            nexus::NexusRuntimeCatalogV1,
            parameter::{CustomParameter, Parameter},
        };

        let app = crate::mk_app_state_for_tests();
        let available = app.query_fanout_inflight.available_bytes();
        let headers = axum::http::HeaderMap::new();
        let method = axum::http::Method::GET;
        let uri = "/v1/explorer/blocks/stream".parse().unwrap();
        let reader = ExplorerReadContext::from_headers(&app, &headers, &method, &uri).unwrap();
        // Corrupt the actual protected native catalog, rather than substituting a mocked
        // StateViewError. Both the initial and retained reader use the real Core decoder.
        let mut world = app.state.world.block();
        world
            .parameters
            .get_mut()
            .set_parameter(Parameter::Custom(CustomParameter::new(
                NexusRuntimeCatalogV1::parameter_id(),
                iroha_primitives::json::Json::new(norito::json!({"version": 255})),
            )));
        world.commit();
        let auth =
            crate::history_producer::HistoryProducerOwner::authentication_read(&app).unwrap();
        let native = app
            .state
            .try_with_authorization_view(auth.allocation_context(), |_| ())
            .unwrap_err();
        assert!(matches!(
            native,
            iroha_core::state::StateViewError::Runtime(_)
        ));
        let expected = native.to_string();
        drop(auth);
        for error in [
            ExplorerReadContext::from_headers(&app, &headers, &method, &uri)
                .err()
                .unwrap(),
            reader.current_visibility().unwrap_err(),
        ] {
            match error {
                Error::Query(ValidationFail::InternalError(message)) => {
                    assert_eq!(message, expected);
                }
                other => panic!("malformed native catalog must remain internal: {other:?}"),
            }
        }
        drop(reader);
        assert_eq!(app.query_fanout_inflight.available_bytes(), available);
    }

    #[test]
    fn stream_control_cannot_outlive_its_original_weighted_native_layout_lease() {
        let app = crate::mk_app_state_for_tests();
        let available = app.query_fanout_inflight.available_bytes();
        let owner = capture(&app);
        let clone = owner.clone();
        assert_eq!(owner.admitted_height(), 1);
        assert!(!owner.can_read_all());
        assert!(owner.caller().is_none());
        let scope = owner.scope_owner(*owner.baseline()).unwrap();
        drop(owner);
        drop(clone);
        assert!(app.query_fanout_inflight.available_bytes() < available);
        assert_eq!(scope.as_slice(), &[DataSpaceId::UNIVERSAL]);
        drop(scope);
        assert_eq!(app.query_fanout_inflight.available_bytes(), available);
    }

    #[tokio::test]
    async fn original_non_unpin_stream_body_and_extracted_frames_retain_control() {
        let app = crate::mk_app_state_for_tests();
        let available = app.query_fanout_inflight.available_bytes();
        let owner = capture(&app);
        let source = futures_util::stream::unfold(false, |emitted| async move {
            if emitted {
                futures_util::future::pending::<()>().await;
                None
            } else {
                Some((
                    Ok::<_, axum::Error>(Frame::data(Bytes::from_static(b"control"))),
                    true,
                ))
            }
        });
        let mut body = owner.body(StreamBody::new(source)).unwrap();
        drop(owner);
        let data = body.frame().await.unwrap().unwrap().into_data().unwrap();
        let clone = data.clone();
        assert!(futures_util::poll!(body.frame()).is_pending());
        drop(body);
        drop(data);
        assert!(app.query_fanout_inflight.available_bytes() < available);
        drop(clone);
        assert_eq!(app.query_fanout_inflight.available_bytes(), available);
    }

    #[test]
    fn stream_control_refuses_before_copying_an_unadmitted_caller() {
        let mut app = crate::mk_app_state_for_tests();
        Arc::get_mut(&mut app).unwrap().query_fanout_inflight =
            crate::ByteWeightedMemoryPool::new(1).unwrap();
        let available = app.query_fanout_inflight.available_bytes();
        let keys =
            iroha_crypto::KeyPair::try_from_seed(vec![0x71; 32], iroha_crypto::Algorithm::Ed25519)
                .unwrap();
        let caller = AccountId::new(keys.public_key().clone());
        assert!(
            StreamControlOwner::capture(
                app.clone(),
                Some(&caller),
                FixedRouteScope::default(),
                false,
                1
            )
            .is_err()
        );
        assert_eq!(app.query_fanout_inflight.available_bytes(), available);
    }
}
