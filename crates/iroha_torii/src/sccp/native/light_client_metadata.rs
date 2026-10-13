//! Light-client metadata uses the same original request worker and response pool.
use super::*;
use crate::sccp::CoveringQuery;
use iroha_core::{
    smartcontracts::isi::sccp::read::native::light_client_metadata as source, state::StateReadOnly,
};

#[derive(Debug, Clone, Copy)]
#[allow(
    variant_size_differences,
    reason = "the bounded checkpoint coordinates stay inline without an unadmitted heap allocation"
)]
pub(super) enum Selection {
    Clients,
    Detail(SccpNetworkV1),
    Sets(SccpNetworkV1),
    Checkpoints(SccpNetworkV1, u64),
}
impl Selection {
    pub(super) fn route(self) -> RouteDescriptor {
        match self {
            Self::Clients => sccp::LIGHT_CLIENTS,
            Self::Detail(_) => sccp::LIGHT_CLIENT,
            Self::Sets(_) => sccp::LIGHT_CLIENT_SETS,
            Self::Checkpoints(..) => sccp::LIGHT_CLIENT_CHECKPOINTS,
        }
    }
}
pub(super) fn produce(
    selection: Selection,
    view: &impl StateReadOnly,
    budget: &iroha_allocation::AllocationBudget,
    control: SccpNativeReadControl<'_>,
    owner: &HistoryProducerOwner,
    (format, maximum): (ResponseFormat, usize),
    headers: &HeaderMap,
) -> Result<Result<PreparedResponse, Error>, SccpNativeReadError> {
    Ok(match selection {
        Selection::Clients => encode(
            source::clients(view, budget, control)?,
            owner,
            format,
            maximum,
            false,
            headers,
        ),
        Selection::Detail(network) => encode(
            source::detail(view, network, budget, control)?,
            owner,
            format,
            maximum,
            false,
            headers,
        ),
        Selection::Sets(network) => encode(
            source::sets(view, network, budget, control)?,
            owner,
            format,
            maximum,
            false,
            headers,
        ),
        Selection::Checkpoints(network, covering) => encode(
            source::checkpoints(view, network, covering, budget, control)?,
            owner,
            format,
            maximum,
            false,
            headers,
        ),
    })
}
pub async fn handler_light_clients(
    State(app): State<SharedAppState>,
    Extension(RouteExecutionDeadline(deadline)): Extension<RouteExecutionDeadline>,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Result<Response, Error> {
    serve(
        app,
        super::Selection::LightClientMetadata(Selection::Clients),
        deadline,
        headers,
        remote,
    )
    .await
}
pub async fn handler_light_client(
    State(app): State<SharedAppState>,
    Path(network): Path<String>,
    Extension(RouteExecutionDeadline(deadline)): Extension<RouteExecutionDeadline>,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Result<Response, Error> {
    match crate::sccp::parse_network(&network) {
        Ok(network) => {
            serve(
                app,
                super::Selection::LightClientMetadata(Selection::Detail(network)),
                deadline,
                headers,
                remote,
            )
            .await
        }
        Err(response) => Ok(response),
    }
}
pub async fn handler_light_client_sets(
    State(app): State<SharedAppState>,
    Path(network): Path<String>,
    Extension(RouteExecutionDeadline(deadline)): Extension<RouteExecutionDeadline>,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Result<Response, Error> {
    match crate::sccp::parse_network(&network) {
        Ok(network) => {
            serve(
                app,
                super::Selection::LightClientMetadata(Selection::Sets(network)),
                deadline,
                headers,
                remote,
            )
            .await
        }
        Err(response) => Ok(response),
    }
}
pub async fn handler_light_client_checkpoints(
    State(app): State<SharedAppState>,
    Path(network): Path<String>,
    NoritoStringQuery(query): NoritoStringQuery<CoveringQuery>,
    Extension(RouteExecutionDeadline(deadline)): Extension<RouteExecutionDeadline>,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Result<Response, Error> {
    let selection = (|| {
        let network = crate::sccp::parse_network(&network)?;
        let covering = query
            .covering
            .as_deref()
            .ok_or_else(|| invalid("covering is required"))?;
        let covering = crate::sccp::parse_number(Some(covering), 0_u64)?;
        Ok::<_, Response>(Selection::Checkpoints(network, covering))
    })();
    match selection {
        Ok(selection) => {
            serve(
                app,
                super::Selection::LightClientMetadata(selection),
                deadline,
                headers,
                remote,
            )
            .await
        }
        Err(response) => Ok(response),
    }
}
