//! Bounded private TLS transport for the three daemon-owned Musubi publication routes.
//!
//! This dedicated listener accepts only the three exact `/v1/musubi/publication/...` paths.
//! The deployment injects an in-memory TLS server identity. Public listener geometry comes from
//! `iroha_config`; no certificate, key, operator token, or signing material is read from it.
// TODO: Qualify live certificate rotation, independent provider replicas, and the complete
// finalized-State publication chain through the configured stock installation.
use super::{
    MusubiPublicationPrivateDeploymentV1, MusubiPublicationPrivateIngressBuilderV1,
    MusubiPublicationPrivateIngressErrorV1, MusubiPublicationPrivateIngressFutureV1,
    MusubiPublicationPrivateServiceFactoryErrorV1, MusubiPublicationPrivateServiceRunnerV1,
};
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::{
    Request, Response, StatusCode,
    body::Incoming,
    header::{CONTENT_LENGTH, CONTENT_TYPE, HeaderMap},
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use iroha_data_model::musubi::MUSUBI_MAX_CAR_BYTES_V1;
use iroha_futures::supervisor::ShutdownSignal;
use iroha_musubi_service::{
    MUSUBI_MAX_SEED_INGRESS_PLAN_BYTES_V1, MUSUBI_PUBLICATION_AUTHORIZATION_HEADER_V1,
    MUSUBI_PUBLICATION_NORITO_MEDIA_TYPE_V1, MUSUBI_PUBLICATION_SEED_METADATA_HEADER_V1,
    MusubiPublicationPrivateHttpRequestV1, MusubiPublicationPrivateHttpResponseV1,
    MusubiPublicationPrivateRouteV1, MusubiPublicationPrivateServiceV1,
    MusubiPublicationServiceErrorCodeV1, MusubiPublicationServiceErrorResponseV1,
};
use std::{
    convert::Infallible,
    net::{SocketAddr, TcpListener},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::TcpListener as AsyncTcpListener,
    sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc},
    task::JoinSet,
};
use tokio_rustls::{TlsAcceptor, rustls::ServerConfig};

const MAX_HEADER_BYTES: usize = 160 * 1024;
const MAX_CONTROL_BODY_BYTES: usize = 8 * 1024 * 1024;
const MAX_AUTH_HEADER_BYTES: usize = 64 * 1024;
const MAX_SEED_METADATA_HEADER_BYTES: usize = 64 * 1024;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_BODY_TIMEOUT: Duration = Duration::from_secs(120);
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Non-secret, bounded listener settings projected from `iroha_config`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MusubiPublicationPrivateTlsSettingsV1 {
    /// Socket bound before a publication child is supervised.
    pub bind: SocketAddr,
    /// Maximum concurrent TLS connections and admitted request buffers.
    pub max_inflight_requests: u16,
}
impl MusubiPublicationPrivateTlsSettingsV1 {
    /// Copy only public listener settings from the daemon configuration.
    #[must_use]
    pub fn from_config(config: &iroha_config::parameters::actual::MusubiPublication) -> Self {
        Self {
            bind: config.private_tls_bind,
            max_inflight_requests: config.max_inflight_requests,
        }
    }

    fn validate(&self) -> Result<(), MusubiPublicationPrivateServiceFactoryErrorV1> {
        if self.max_inflight_requests == 0 || self.max_inflight_requests > 4 {
            return Err(MusubiPublicationPrivateServiceFactoryErrorV1::Unqualified);
        }
        Ok(())
    }
}

/// Pre-bound private TLS ingress builder with a runtime-only server identity.
pub struct MusubiPublicationPrivateTlsIngressBuilderV1 {
    settings: MusubiPublicationPrivateTlsSettingsV1,
    listener: TcpListener,
    tls: Arc<ServerConfig>,
}
impl core::fmt::Debug for MusubiPublicationPrivateTlsIngressBuilderV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("MusubiPublicationPrivateTlsIngressBuilderV1")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}
impl MusubiPublicationPrivateTlsIngressBuilderV1 {
    /// Bind using only the public listener projection from `iroha_config`.
    ///
    /// # Errors
    /// Refuses invalid geometry or an unavailable bind before a publication child starts.
    pub fn from_config(
        config: &iroha_config::parameters::actual::MusubiPublication,
        tls: Arc<ServerConfig>,
    ) -> Result<Self, MusubiPublicationPrivateServiceFactoryErrorV1> {
        Self::new(
            MusubiPublicationPrivateTlsSettingsV1::from_config(config),
            tls,
        )
    }

    /// Bind one private listener from non-secret config and a runtime-held TLS identity.
    ///
    /// TLS early data is disabled so a signed publication request cannot be processed in 0-RTT.
    /// Only HTTP/1.1 is advertised; each connection carries at most one request.
    ///
    /// # Errors
    /// Refuses invalid geometry or an unavailable bind before a publication child starts.
    pub fn new(
        settings: MusubiPublicationPrivateTlsSettingsV1,
        tls: Arc<ServerConfig>,
    ) -> Result<Self, MusubiPublicationPrivateServiceFactoryErrorV1> {
        settings.validate()?;
        let listener = TcpListener::bind(settings.bind)
            .map_err(|_| MusubiPublicationPrivateServiceFactoryErrorV1::Unavailable)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| MusubiPublicationPrivateServiceFactoryErrorV1::Unavailable)?;
        let mut tls = Arc::unwrap_or_clone(tls);
        tls.max_early_data_size = 0;
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            settings,
            listener,
            tls: Arc::new(tls),
        })
    }

    /// Return the actual bound socket, including an ephemeral test port when configured.
    ///
    /// # Errors
    /// Returns a redacted unavailable error if the operating system loses the listener.
    pub fn local_addr(&self) -> Result<SocketAddr, MusubiPublicationPrivateServiceFactoryErrorV1> {
        self.listener
            .local_addr()
            .map_err(|_| MusubiPublicationPrivateServiceFactoryErrorV1::Unavailable)
    }
}
impl MusubiPublicationPrivateIngressBuilderV1 for MusubiPublicationPrivateTlsIngressBuilderV1 {
    fn build(
        self: Box<Self>,
        service: MusubiPublicationPrivateServiceV1,
    ) -> Result<MusubiPublicationPrivateDeploymentV1, MusubiPublicationPrivateServiceFactoryErrorV1>
    {
        Ok(MusubiPublicationPrivateDeploymentV1::new(Box::new(
            MusubiPublicationPrivateTlsRunnerV1 {
                settings: self.settings,
                listener: self.listener,
                tls: self.tls,
                dispatch: Arc::new(ServiceDispatchV1(Mutex::new(service))),
                active_dispatches: Arc::new(ActiveDispatchesV1::default()),
            },
        )))
    }
}

struct OwnedHttpRequestV1 {
    method: String,
    path: String,
    content_type: String,
    authorization: Option<String>,
    seed_ingress_metadata: Option<String>,
    body: Vec<u8>,
}
impl OwnedHttpRequestV1 {
    fn borrowed(&self) -> MusubiPublicationPrivateHttpRequestV1<'_> {
        MusubiPublicationPrivateHttpRequestV1 {
            method: &self.method,
            path: &self.path,
            content_type: &self.content_type,
            authorization: self.authorization.as_deref(),
            seed_ingress_metadata: self.seed_ingress_metadata.as_deref(),
            body: &self.body,
        }
    }
}
trait PrivateDispatchV1: Send + Sync {
    fn handle(
        &self,
        request: OwnedHttpRequestV1,
    ) -> Result<MusubiPublicationPrivateHttpResponseV1, MusubiPublicationPrivateIngressErrorV1>;
}
struct ServiceDispatchV1(Mutex<MusubiPublicationPrivateServiceV1>);
impl PrivateDispatchV1 for ServiceDispatchV1 {
    fn handle(
        &self,
        request: OwnedHttpRequestV1,
    ) -> Result<MusubiPublicationPrivateHttpResponseV1, MusubiPublicationPrivateIngressErrorV1>
    {
        let mut service = self
            .0
            .lock()
            .map_err(|_| MusubiPublicationPrivateIngressErrorV1::Unqualified)?;
        Ok(service.handle(request.borrowed()))
    }
}

#[derive(Default)]
struct ActiveDispatchesV1 {
    count: AtomicUsize,
    drained: Notify,
}
impl ActiveDispatchesV1 {
    fn lease(self: &Arc<Self>) -> ActiveDispatchLeaseV1 {
        self.count.fetch_add(1, Ordering::AcqRel);
        ActiveDispatchLeaseV1(Arc::clone(self))
    }
    async fn wait_for_drain(&self) {
        loop {
            // Register before inspecting the count so the final drop cannot race past us.
            let notified = self.drained.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.count.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }
}
struct ActiveDispatchLeaseV1(Arc<ActiveDispatchesV1>);
impl Drop for ActiveDispatchLeaseV1 {
    fn drop(&mut self) {
        if self.0.count.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.drained.notify_one();
        }
    }
}

struct MusubiPublicationPrivateTlsRunnerV1 {
    settings: MusubiPublicationPrivateTlsSettingsV1,
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    dispatch: Arc<dyn PrivateDispatchV1>,
    active_dispatches: Arc<ActiveDispatchesV1>,
}
impl MusubiPublicationPrivateServiceRunnerV1 for MusubiPublicationPrivateTlsRunnerV1 {
    fn serve(self: Box<Self>, shutdown: ShutdownSignal) -> MusubiPublicationPrivateIngressFutureV1 {
        Box::pin(async move { self.run(shutdown).await })
    }
}
impl MusubiPublicationPrivateTlsRunnerV1 {
    async fn run(
        self: Box<Self>,
        shutdown: ShutdownSignal,
    ) -> Result<(), MusubiPublicationPrivateIngressErrorV1> {
        let Self {
            settings,
            listener,
            tls,
            dispatch,
            active_dispatches,
        } = *self;
        let listener = AsyncTcpListener::from_std(listener)
            .map_err(|_| MusubiPublicationPrivateIngressErrorV1::Unavailable)?;
        let acceptor = TlsAcceptor::from(tls);
        let permits = Arc::new(Semaphore::new(usize::from(settings.max_inflight_requests)));
        let (fatal_tx, mut fatal_rx) = mpsc::unbounded_channel();
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                () = shutdown.receive() => {
                    connections.abort_all();
                    while connections.join_next().await.is_some() {}
                    // Cancellation of an HTTP task cannot cancel a blocking service call.
                    // Its lease retains the dispatch owner and durable custody until completion.
                    // The outer supervisor may time out its bounded wait, but cannot free that
                    // owner while the blocking call remains active.
                    active_dispatches.wait_for_drain().await;
                    // Every physical failure is queued before its active lease is released.
                    // Requested shutdown must not erase a failure observed during that drain.
                    return match fatal_rx.try_recv() {
                        Ok(error) => Err(error),
                        Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected) => Ok(()),
                    };
                }
                Some(error) = fatal_rx.recv() => return Err(error),
                Some(result) = connections.join_next(), if !connections.is_empty() => {
                    if result.is_err() {
                        return Err(MusubiPublicationPrivateIngressErrorV1::Unqualified);
                    }
                }
                accepted = listener.accept() => {
                    let (stream, _) = accepted
                        .map_err(|_| MusubiPublicationPrivateIngressErrorV1::Unavailable)?;
                    let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                        // Capacity is local operational deferral, never publication invalidity.
                        continue;
                    };
                    let acceptor = acceptor.clone();
                    let dispatch = Arc::clone(&dispatch);
                    let active_dispatches = Arc::clone(&active_dispatches);
                    let fatal_tx = fatal_tx.clone();
                    let shutdown = shutdown.clone();
                    connections.spawn(async move {
                        serve_connection(
                            stream,
                            acceptor,
                            dispatch,
                            active_dispatches,
                            fatal_tx,
                            shutdown,
                            Arc::new(permit),
                        )
                        .await;
                    });
                }
            }
        }
    }
}

async fn serve_connection(
    stream: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
    dispatch: Arc<dyn PrivateDispatchV1>,
    active_dispatches: Arc<ActiveDispatchesV1>,
    fatal_tx: mpsc::UnboundedSender<MusubiPublicationPrivateIngressErrorV1>,
    shutdown: ShutdownSignal,
    permit: Arc<OwnedSemaphorePermit>,
) {
    let Ok(Ok(stream)) = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await
    else {
        return;
    };
    let service = service_fn(move |request: Request<Incoming>| {
        let dispatch = Arc::clone(&dispatch);
        let active_dispatches = Arc::clone(&active_dispatches);
        let fatal_tx = fatal_tx.clone();
        let permit = Arc::clone(&permit);
        async move {
            Ok::<_, Infallible>(
                handle_http(request, dispatch, active_dispatches, fatal_tx, permit).await,
            )
        }
    });
    let mut http = hyper::server::conn::http1::Builder::new();
    http.timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .max_headers(32)
        .max_buf_size(MAX_HEADER_BYTES)
        .keep_alive(false);
    let connection = http.serve_connection(TokioIo::new(stream), service);
    tokio::pin!(connection);
    tokio::select! {
        () = shutdown.receive() => {}
        _ = &mut connection => {}
    }
}

async fn handle_http(
    request: Request<Incoming>,
    dispatch: Arc<dyn PrivateDispatchV1>,
    active_dispatches: Arc<ActiveDispatchesV1>,
    fatal_tx: mpsc::UnboundedSender<MusubiPublicationPrivateIngressErrorV1>,
    permit: Arc<OwnedSemaphorePermit>,
) -> Response<Full<Bytes>> {
    let (parts, body) = request.into_parts();
    if parts.uri.query().is_some() {
        return error_response(
            StatusCode::NOT_FOUND,
            MusubiPublicationServiceErrorCodeV1::RouteNotFound,
        );
    }
    let path = parts.uri.path();
    let Some(route) = MusubiPublicationPrivateRouteV1::parse(path) else {
        return error_response(
            StatusCode::NOT_FOUND,
            MusubiPublicationServiceErrorCodeV1::RouteNotFound,
        );
    };
    if parts.method.as_str() != "POST" {
        return error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            MusubiPublicationServiceErrorCodeV1::MethodInvalid,
        );
    }
    let headers = &parts.headers;
    if headers.contains_key("transfer-encoding")
        || headers.contains_key("content-encoding")
        || headers.contains_key("expect")
    {
        return error_response(
            StatusCode::BAD_REQUEST,
            MusubiPublicationServiceErrorCodeV1::RequestInvalid,
        );
    }
    let Some(content_type) = single_header(headers, CONTENT_TYPE).ok().flatten() else {
        return error_response(
            StatusCode::BAD_REQUEST,
            MusubiPublicationServiceErrorCodeV1::RequestInvalid,
        );
    };
    let Some(authorization) = single_header(headers, MUSUBI_PUBLICATION_AUTHORIZATION_HEADER_V1)
        .ok()
        .flatten()
    else {
        return error_response(
            StatusCode::BAD_REQUEST,
            MusubiPublicationServiceErrorCodeV1::AuthorizationInvalid,
        );
    };
    let Ok(seed_metadata) = single_header(headers, MUSUBI_PUBLICATION_SEED_METADATA_HEADER_V1)
    else {
        return error_response(
            StatusCode::BAD_REQUEST,
            MusubiPublicationServiceErrorCodeV1::RequestInvalid,
        );
    };
    if content_type.len() > 128
        || authorization.len() > MAX_AUTH_HEADER_BYTES
        || seed_metadata.is_some_and(|value| value.len() > MAX_SEED_METADATA_HEADER_BYTES)
        || (route != MusubiPublicationPrivateRouteV1::SeedIngress && seed_metadata.is_some())
        || single_header(headers, "host").ok().flatten().is_none()
    {
        return error_response(
            StatusCode::BAD_REQUEST,
            MusubiPublicationServiceErrorCodeV1::RequestInvalid,
        );
    }
    let Some(length) = single_header(headers, CONTENT_LENGTH)
        .ok()
        .flatten()
        .and_then(canonical_content_length)
    else {
        return error_response(
            StatusCode::BAD_REQUEST,
            MusubiPublicationServiceErrorCodeV1::RequestInvalid,
        );
    };
    let maximum = if route == MusubiPublicationPrivateRouteV1::SeedIngress {
        max_seed_body_bytes()
    } else {
        MAX_CONTROL_BODY_BYTES
    };
    if length > maximum {
        return error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            MusubiPublicationServiceErrorCodeV1::RequestInvalid,
        );
    }
    let body = match tokio::time::timeout(REQUEST_BODY_TIMEOUT, read_exact_body(body, length)).await
    {
        Ok(Ok(body)) => body,
        Ok(Err(BodyReadErrorV1::Unavailable)) => return unavailable_response(),
        _ => {
            return error_response(
                StatusCode::BAD_REQUEST,
                MusubiPublicationServiceErrorCodeV1::RequestInvalid,
            );
        }
    };
    let owned = OwnedHttpRequestV1 {
        method: parts.method.as_str().to_owned(),
        path: path.to_owned(),
        content_type: content_type.to_owned(),
        authorization: Some(authorization.to_owned()),
        seed_ingress_metadata: seed_metadata.map(str::to_owned),
        body,
    };
    dispatch_recoverably(dispatch, owned, active_dispatches.lease(), fatal_tx, permit).await
}

async fn dispatch_recoverably(
    dispatch: Arc<dyn PrivateDispatchV1>,
    owned: OwnedHttpRequestV1,
    lease: ActiveDispatchLeaseV1,
    fatal_tx: mpsc::UnboundedSender<MusubiPublicationPrivateIngressErrorV1>,
    permit: Arc<OwnedSemaphorePermit>,
) -> Response<Full<Bytes>> {
    let handled = crate::panic_recovery::join_recoverable(
        crate::panic_recovery::spawn_blocking_recoverable(move || {
            let _lease = lease;
            // A cancelled HTTP waiter must neither free physical admission nor hide a
            // terminal provider failure. Both owners survive until this call completes.
            let _permit = permit;
            let handled = iroha_panic_hook::catch_unwind_suppressed(|| dispatch.handle(owned))
                .unwrap_or(Err(MusubiPublicationPrivateIngressErrorV1::Unqualified));
            if let Err(error) = &handled {
                let _ = fatal_tx.send(*error);
            }
            // Drained means the last physical owner has been released, including its service.
            drop(dispatch);
            handled
        }),
    )
    .await;
    match handled {
        Ok(Ok(response)) => service_response(response),
        Ok(Err(_)) | Err(_) => unavailable_response(),
    }
}

fn max_seed_body_bytes() -> usize {
    40_usize
        .checked_add(MUSUBI_MAX_SEED_INGRESS_PLAN_BYTES_V1)
        .and_then(|length| {
            usize::try_from(MUSUBI_MAX_CAR_BYTES_V1)
                .ok()
                .and_then(|car| length.checked_add(car))
        })
        .expect("fixed Musubi seed body bound fits supported hosts")
}

fn single_header(
    headers: &HeaderMap,
    name: impl hyper::header::AsHeaderName,
) -> Result<Option<&str>, ()> {
    let mut values = headers.get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(());
    }
    first
        .map(|value| value.to_str().map_err(|_| ()))
        .transpose()
}

fn canonical_content_length(value: &str) -> Option<usize> {
    let parsed = value.parse::<usize>().ok()?;
    (parsed.to_string() == value).then_some(parsed)
}

enum BodyReadErrorV1 {
    Invalid,
    Unavailable,
}
async fn read_exact_body(
    mut body: Incoming,
    expected_length: usize,
) -> Result<Vec<u8>, BodyReadErrorV1> {
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let chunk = frame
            .map_err(|_| BodyReadErrorV1::Invalid)?
            .into_data()
            .map_err(|_| BodyReadErrorV1::Invalid)?;
        if bytes
            .len()
            .checked_add(chunk.len())
            .is_none_or(|length| length > expected_length)
        {
            return Err(BodyReadErrorV1::Invalid);
        }
        bytes
            .try_reserve_exact(chunk.len())
            .map_err(|_| BodyReadErrorV1::Unavailable)?;
        bytes.extend_from_slice(&chunk);
    }
    (bytes.len() == expected_length)
        .then_some(bytes)
        .ok_or(BodyReadErrorV1::Invalid)
}

fn service_response(response: MusubiPublicationPrivateHttpResponseV1) -> Response<Full<Bytes>> {
    let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, response.content_type)
        .body(Full::new(Bytes::from(response.body)))
        .expect("fixed private service response headers must be valid")
}
fn error_response(
    status: StatusCode,
    code: MusubiPublicationServiceErrorCodeV1,
) -> Response<Full<Bytes>> {
    let body = norito::encode_canonical(&MusubiPublicationServiceErrorResponseV1 {
        version: 1,
        code,
        retryable: false,
    })
    .expect("fixed bounded private ingress error must encode");
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, MUSUBI_PUBLICATION_NORITO_MEDIA_TYPE_V1)
        .body(Full::new(Bytes::from(body)))
        .expect("fixed private ingress response headers must be valid")
}
fn unavailable_response() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .body(Full::new(Bytes::new()))
        .expect("fixed unavailable response must be valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::Ipv4Addr, sync::Mutex};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio_rustls::{
        TlsConnector,
        rustls::{
            ClientConfig, RootCertStore,
            pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
        },
    };

    #[derive(Default)]
    struct RecordingDispatchV1 {
        requests: Mutex<Vec<OwnedHttpRequestV1>>,
    }
    impl PrivateDispatchV1 for RecordingDispatchV1 {
        fn handle(
            &self,
            request: OwnedHttpRequestV1,
        ) -> Result<MusubiPublicationPrivateHttpResponseV1, MusubiPublicationPrivateIngressErrorV1>
        {
            self.requests.lock().expect("test lock").push(request);
            Ok(MusubiPublicationPrivateHttpResponseV1 {
                status: 200,
                content_type: MUSUBI_PUBLICATION_NORITO_MEDIA_TYPE_V1,
                body: b"accepted".to_vec(),
            })
        }
    }
    fn tls_identity() -> (Arc<ServerConfig>, Arc<ClientConfig>) {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
                .expect("test TLS identity");
        let certificate = cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
        let mut server = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], key)
            .expect("test server config");
        server.max_early_data_size = 4_096;
        let mut roots = RootCertStore::empty();
        roots.add(certificate).expect("test root");
        let client = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        (Arc::new(server), Arc::new(client))
    }
    fn settings() -> MusubiPublicationPrivateTlsSettingsV1 {
        MusubiPublicationPrivateTlsSettingsV1 {
            bind: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            max_inflight_requests: 2,
        }
    }
    #[tokio::test]
    async fn panicking_dispatch_signals_supervisor_and_releases_lease() {
        struct PanickingDispatchV1;
        impl PrivateDispatchV1 for PanickingDispatchV1 {
            fn handle(
                &self,
                _request: OwnedHttpRequestV1,
            ) -> Result<
                MusubiPublicationPrivateHttpResponseV1,
                MusubiPublicationPrivateIngressErrorV1,
            > {
                assert!(iroha_panic_hook::is_suppressed());
                panic!("injected private dispatch failure");
            }
        }

        let active = Arc::new(ActiveDispatchesV1::default());
        let capacity = Arc::new(Semaphore::new(1));
        let (fatal_tx, mut fatal_rx) = mpsc::unbounded_channel();
        let response = dispatch_recoverably(
            Arc::new(PanickingDispatchV1),
            OwnedHttpRequestV1 {
                method: "POST".to_owned(),
                path: "/v1/musubi/publication/storage-coordinate".to_owned(),
                content_type: MUSUBI_PUBLICATION_NORITO_MEDIA_TYPE_V1.to_owned(),
                authorization: Some("test-auth".to_owned()),
                seed_ingress_metadata: None,
                body: Vec::new(),
            },
            active.lease(),
            fatal_tx,
            Arc::new(capacity.clone().try_acquire_owned().unwrap()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            fatal_rx.recv().await,
            Some(MusubiPublicationPrivateIngressErrorV1::Unqualified)
        );
        active.wait_for_drain().await;
        assert_eq!(active.count.load(Ordering::SeqCst), 0);
        assert_eq!(capacity.available_permits(), 1);
    }

    #[tokio::test]
    async fn cancelled_http_waiter_retains_physical_capacity_and_reports_failures() {
        struct DelayedDispatchV1 {
            entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
            release: Mutex<std::sync::mpsc::Receiver<()>>,
            outcome: u8,
        }
        impl PrivateDispatchV1 for DelayedDispatchV1 {
            fn handle(
                &self,
                request: OwnedHttpRequestV1,
            ) -> Result<
                MusubiPublicationPrivateHttpResponseV1,
                MusubiPublicationPrivateIngressErrorV1,
            > {
                assert!(iroha_panic_hook::is_suppressed());
                assert_eq!(request.body, b"body");
                self.entered
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap()
                    .send(())
                    .unwrap();
                self.release.lock().unwrap().recv().unwrap();
                match self.outcome {
                    0 => Ok(MusubiPublicationPrivateHttpResponseV1 {
                        status: 200,
                        content_type: MUSUBI_PUBLICATION_NORITO_MEDIA_TYPE_V1,
                        body: Vec::new(),
                    }),
                    1 => Err(MusubiPublicationPrivateIngressErrorV1::Unavailable),
                    _ => panic!("delayed physical dispatch failure"),
                }
            }
        }

        for outcome in 0..3 {
            let active = Arc::new(ActiveDispatchesV1::default());
            let capacity = Arc::new(Semaphore::new(1));
            let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let dispatch = Arc::new(DelayedDispatchV1 {
                entered: Mutex::new(Some(entered_tx)),
                release: Mutex::new(release_rx),
                outcome,
            });
            let weak_dispatch = Arc::downgrade(&dispatch);
            let (fatal_tx, mut fatal_rx) = mpsc::unbounded_channel();
            let mut response = Box::pin(dispatch_recoverably(
                dispatch,
                OwnedHttpRequestV1 {
                    method: "POST".to_owned(),
                    path: "/v1/musubi/publication/storage-coordinate".to_owned(),
                    content_type: MUSUBI_PUBLICATION_NORITO_MEDIA_TYPE_V1.to_owned(),
                    authorization: Some("test-auth".to_owned()),
                    seed_ingress_metadata: None,
                    body: b"body".to_vec(),
                },
                active.lease(),
                fatal_tx,
                Arc::new(capacity.clone().try_acquire_owned().unwrap()),
            ));
            tokio::select! {
                _ = &mut response => panic!("physical dispatch must wait for release"),
                entered = entered_rx => entered.expect("original physical worker entered"),
            }
            // Model the HTTP task disappearing after it handed off its original body.
            drop(response);
            assert!(weak_dispatch.upgrade().is_some());
            assert_eq!(active.count.load(Ordering::Acquire), 1);
            assert_eq!(capacity.available_permits(), 0);
            assert!(capacity.clone().try_acquire_owned().is_err());
            assert!(matches!(
                fatal_rx.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));

            release_tx.send(()).unwrap();
            let expected = match outcome {
                0 => None,
                1 => Some(MusubiPublicationPrivateIngressErrorV1::Unavailable),
                _ => Some(MusubiPublicationPrivateIngressErrorV1::Unqualified),
            };
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(5), fatal_rx.recv())
                    .await
                    .unwrap(),
                expected,
                "the physical owner reports failure even after cancellation"
            );
            if expected.is_some() {
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(5), fatal_rx.recv())
                        .await
                        .unwrap(),
                    None,
                    "a physical failure is reported exactly once"
                );
            }
            tokio::time::timeout(Duration::from_secs(5), active.wait_for_drain())
                .await
                .unwrap();
            assert_eq!(capacity.available_permits(), 1);
            assert!(weak_dispatch.upgrade().is_none());
        }
    }

    async fn send_tls_request(
        address: SocketAddr,
        client: Arc<ClientConfig>,
        request: &[u8],
    ) -> Vec<u8> {
        let tcp = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect private loopback listener");
        let server_name = ServerName::try_from("localhost").expect("literal TLS server name");
        let mut tls = TlsConnector::from(client)
            .connect(server_name, tcp)
            .await
            .expect("private TLS handshake");
        tls.write_all(request).await.expect("send private request");
        let mut response = Vec::new();
        let mut chunk = [0_u8; 4096];
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match tls.read(&mut chunk).await {
                    Ok(0) => break,
                    Ok(length) => response.extend_from_slice(&chunk[..length]),
                    Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(error) => panic!("read private response: {error}"),
                }
                if response.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
        })
        .await
        .expect("private response timeout");
        response
    }

    #[test]
    fn settings_reject_unbounded_concurrency() {
        let config = iroha_config::parameters::actual::MusubiPublication {
            private_tls_bind: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            ..iroha_config::parameters::actual::MusubiPublication::default()
        };
        let projected = MusubiPublicationPrivateTlsSettingsV1::from_config(&config);
        assert_eq!(projected.bind, config.private_tls_bind);
        assert_eq!(
            projected.max_inflight_requests,
            config.max_inflight_requests
        );
        assert!(projected.validate().is_ok());
        for maximum in [0, 5] {
            let mut invalid = projected;
            invalid.max_inflight_requests = maximum;
            assert_eq!(
                invalid.validate(),
                Err(MusubiPublicationPrivateServiceFactoryErrorV1::Unqualified)
            );
        }
        assert_eq!(
            max_seed_body_bytes(),
            40 + 24 * 1024 * 1024 + 96 * 1024 * 1024
        );
    }

    #[test]
    fn prebound_tls_builder_disables_early_data_and_rejects_bind_collision() {
        let (server, _) = tls_identity();
        let config = iroha_config::parameters::actual::MusubiPublication {
            private_tls_bind: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            ..iroha_config::parameters::actual::MusubiPublication::default()
        };
        let first =
            MusubiPublicationPrivateTlsIngressBuilderV1::from_config(&config, Arc::clone(&server))
                .expect("private listener binds from non-secret config");
        assert_eq!(first.tls.max_early_data_size, 0);
        assert_eq!(first.tls.alpn_protocols, vec![b"http/1.1".to_vec()]);
        let actual = first.local_addr().expect("bound address");
        assert_ne!(actual.port(), 0);
        let mut occupied = settings();
        occupied.bind = actual;
        assert!(matches!(
            MusubiPublicationPrivateTlsIngressBuilderV1::new(occupied, server),
            Err(MusubiPublicationPrivateServiceFactoryErrorV1::Unavailable)
        ));
    }

    #[test]
    fn header_and_response_helpers_preserve_exact_transport_inputs() {
        let mut headers = HeaderMap::new();
        headers.insert("x-test", "one".parse().expect("header"));
        assert_eq!(single_header(&headers, "x-test"), Ok(Some("one")));
        headers.append("x-test", "two".parse().expect("header"));
        assert_eq!(single_header(&headers, "x-test"), Err(()));
        assert_eq!(canonical_content_length("3"), Some(3));
        assert_eq!(canonical_content_length("03"), None);
        assert_eq!(canonical_content_length("+3"), None);
        let response = service_response(MusubiPublicationPrivateHttpResponseV1 {
            status: 201,
            content_type: MUSUBI_PUBLICATION_NORITO_MEDIA_TYPE_V1,
            body: b"ok".to_vec(),
        });
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            error_response(
                StatusCode::NOT_FOUND,
                MusubiPublicationServiceErrorCodeV1::RouteNotFound
            )
            .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            unavailable_response().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn private_tls_loopback_enforces_route_headers_body_bound_and_shutdown() {
        let (server, client) = tls_identity();
        let builder = MusubiPublicationPrivateTlsIngressBuilderV1::new(settings(), server)
            .expect("prebind private TLS listener");
        let address = builder.local_addr().expect("bound private address");
        let dispatch = Arc::new(RecordingDispatchV1::default());
        let runner = MusubiPublicationPrivateTlsRunnerV1 {
            settings: builder.settings,
            listener: builder.listener,
            tls: builder.tls,
            dispatch: dispatch.clone(),
            active_dispatches: Arc::new(ActiveDispatchesV1::default()),
        };
        let shutdown = ShutdownSignal::new();
        let task = tokio::spawn(Box::new(runner).run(shutdown.clone()));
        let route = "/v1/musubi/publication/storage-coordinate";
        let request = format!(
            "POST {route} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-norito\r\n{MUSUBI_PUBLICATION_AUTHORIZATION_HEADER_V1}: test-auth\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc"
        );
        let accepted = send_tls_request(address, Arc::clone(&client), request.as_bytes()).await;
        assert!(accepted.starts_with(b"HTTP/1.1 200"));
        {
            let seen = dispatch.requests.lock().expect("test lock");
            assert_eq!(seen.len(), 1);
            assert_eq!(
                seen[0].borrowed().path,
                "/v1/musubi/publication/storage-coordinate"
            );
            assert_eq!(seen[0].borrowed().body, b"abc");
        }

        let duplicate = format!(
            "POST {route} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-norito\r\n{MUSUBI_PUBLICATION_AUTHORIZATION_HEADER_V1}: one\r\n{MUSUBI_PUBLICATION_AUTHORIZATION_HEADER_V1}: two\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let rejected = send_tls_request(address, Arc::clone(&client), duplicate.as_bytes()).await;
        assert!(rejected.starts_with(b"HTTP/1.1 400"));
        let oversized = format!(
            "POST {route} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-norito\r\n{MUSUBI_PUBLICATION_AUTHORIZATION_HEADER_V1}: one\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            MAX_CONTROL_BODY_BYTES + 1
        );
        let rejected = send_tls_request(address, Arc::clone(&client), oversized.as_bytes()).await;
        assert!(rejected.starts_with(b"HTTP/1.1 413"));
        for path in [
            "/private/v1/musubi/publication/storage-coordinate",
            "/public/v1/musubi/publication/storage-coordinate",
            "/v1/musubi/publication/storage-coordinate?operation=one",
            "/v1/musubi/publication/storage-coordinate/",
            "/v1/musubi/publication/unknown",
            "/v1/musubi/publication/%73torage-coordinate",
        ] {
            let wrong_route = format!(
                "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let rejected =
                send_tls_request(address, Arc::clone(&client), wrong_route.as_bytes()).await;
            assert!(rejected.starts_with(b"HTTP/1.1 404"), "{path}");
        }
        assert_eq!(dispatch.requests.lock().expect("test lock").len(), 1);
        shutdown.send();
        assert!(
            tokio::time::timeout(Duration::from_secs(5), task)
                .await
                .expect("supervised ingress shutdown")
                .expect("runner task")
                .is_ok()
        );
        assert!(tokio::net::TcpStream::connect(address).await.is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dedicated_tls_listener_accepts_only_the_three_exact_publication_paths() {
        let (server, client) = tls_identity();
        let builder = MusubiPublicationPrivateTlsIngressBuilderV1::new(settings(), server)
            .expect("prebind dedicated TLS listener");
        let address = builder.local_addr().expect("bound private address");
        let dispatch = Arc::new(RecordingDispatchV1::default());
        let runner = MusubiPublicationPrivateTlsRunnerV1 {
            settings: builder.settings,
            listener: builder.listener,
            tls: builder.tls,
            dispatch: dispatch.clone(),
            active_dispatches: Arc::new(ActiveDispatchesV1::default()),
        };
        let shutdown = ShutdownSignal::new();
        let task = tokio::spawn(Box::new(runner).run(shutdown.clone()));
        let routes = [
            MusubiPublicationPrivateRouteV1::SeedIngress,
            MusubiPublicationPrivateRouteV1::StorageCoordination,
            MusubiPublicationPrivateRouteV1::ProviderReadback,
        ];
        for (index, route) in routes.into_iter().enumerate() {
            let path = route.path();
            // This component records framing only; the service still owns authorization.
            let request = format!(
                "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-norito\r\n{MUSUBI_PUBLICATION_AUTHORIZATION_HEADER_V1}: transport-only\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx"
            );
            let accepted = send_tls_request(address, Arc::clone(&client), request.as_bytes()).await;
            assert!(accepted.starts_with(b"HTTP/1.1 200"), "{path}");
            {
                let seen = dispatch.requests.lock().expect("test lock");
                assert_eq!(seen.len(), index + 1);
                assert_eq!(seen[index].borrowed().path, path);
                assert_eq!(seen[index].borrowed().body, b"x");
            }
            for rejected_path in [format!("/private{path}"), format!("{path}?selection=one")] {
                let request = format!(
                    "POST {rejected_path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let rejected =
                    send_tls_request(address, Arc::clone(&client), request.as_bytes()).await;
                assert!(rejected.starts_with(b"HTTP/1.1 404"), "{rejected_path}");
                assert_eq!(
                    dispatch.requests.lock().expect("test lock").len(),
                    index + 1
                );
            }
        }
        shutdown.send();
        assert!(
            tokio::time::timeout(Duration::from_secs(5), task)
                .await
                .expect("supervised ingress shutdown")
                .expect("runner task")
                .is_ok()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_drains_blocking_dispatch_and_retains_custody_owner() {
        use std::sync::mpsc;

        struct BlockingDispatchV1 {
            entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
            release: Mutex<mpsc::Receiver<()>>,
            outcome: u8,
        }
        impl PrivateDispatchV1 for BlockingDispatchV1 {
            fn handle(
                &self,
                _request: OwnedHttpRequestV1,
            ) -> Result<
                MusubiPublicationPrivateHttpResponseV1,
                MusubiPublicationPrivateIngressErrorV1,
            > {
                self.entered
                    .lock()
                    .expect("test lock")
                    .take()
                    .expect("first dispatch")
                    .send(())
                    .expect("test awaits dispatch");
                self.release
                    .lock()
                    .expect("test lock")
                    .recv()
                    .expect("release dispatch");
                match self.outcome {
                    0 => Ok(MusubiPublicationPrivateHttpResponseV1 {
                        status: 200,
                        content_type: MUSUBI_PUBLICATION_NORITO_MEDIA_TYPE_V1,
                        body: Vec::new(),
                    }),
                    1 => Err(MusubiPublicationPrivateIngressErrorV1::Unavailable),
                    _ => panic!("physical dispatch failed while shutdown drained"),
                }
            }
        }

        for outcome in 0..3 {
            let (server, client) = tls_identity();
            let builder = MusubiPublicationPrivateTlsIngressBuilderV1::new(settings(), server)
                .expect("prebind private TLS listener");
            let address = builder.local_addr().expect("bound private address");
            let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let dispatch = Arc::new(BlockingDispatchV1 {
                entered: Mutex::new(Some(entered_tx)),
                release: Mutex::new(release_rx),
                outcome,
            });
            let weak_dispatch = Arc::downgrade(&dispatch);
            let runner = MusubiPublicationPrivateTlsRunnerV1 {
                settings: builder.settings,
                listener: builder.listener,
                tls: builder.tls,
                dispatch: dispatch.clone(),
                active_dispatches: Arc::new(ActiveDispatchesV1::default()),
            };
            let shutdown = ShutdownSignal::new();
            let mut task = tokio::spawn(Box::new(runner).run(shutdown.clone()));
            let route = "/v1/musubi/publication/storage-coordinate";
            let request = format!(
                "POST {route} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-norito\r\n{MUSUBI_PUBLICATION_AUTHORIZATION_HEADER_V1}: test-auth\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let request_task =
                tokio::spawn(
                    async move { send_tls_request(address, client, request.as_bytes()).await },
                );
            tokio::time::timeout(Duration::from_secs(5), entered_rx)
                .await
                .expect("dispatch starts")
                .expect("dispatch signal");
            drop(dispatch);
            shutdown.send();
            assert!(
                tokio::time::timeout(Duration::from_millis(100), &mut task)
                    .await
                    .is_err(),
                "shutdown must wait for the blocking service call"
            );
            assert!(
                weak_dispatch.upgrade().is_some(),
                "custody owner remains live"
            );
            release_tx.send(()).expect("release dispatch");
            let expected = match outcome {
                0 => Ok(()),
                1 => Err(MusubiPublicationPrivateIngressErrorV1::Unavailable),
                _ => Err(MusubiPublicationPrivateIngressErrorV1::Unqualified),
            };
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(5), task)
                    .await
                    .expect("drained shutdown")
                    .expect("runner task"),
                expected,
                "shutdown retains the original physical outcome"
            );
            tokio::time::timeout(Duration::from_secs(5), request_task)
                .await
                .expect("cancelled private request returns")
                .expect("private request task");
            assert!(
                weak_dispatch.upgrade().is_none(),
                "custody owner is reclaimed"
            );
        }
    }
}
